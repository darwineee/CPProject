#include "WalletManager.h"
#include <stdexcept>
#include <iostream>
#include <vector>

WalletManager::WalletManager(sqlite3* dbConnection) : db(dbConnection) {
    if (!db) {
        throw std::runtime_error("Invalid database connection");
    }
    initializeWalletTables();
}

WalletManager::~WalletManager() {
}

void WalletManager::executeSQL(const std::string& sql) {
    char* errMsg = nullptr;
    int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::string error = errMsg ? errMsg : "Unknown SQL error";
        sqlite3_free(errMsg);
        throw std::runtime_error("SQL error: " + error);
    }
}

void WalletManager::initializeWalletTables() {
    // Master wallet table (single row, id=1)
    std::string masterWalletTable = R"(
        CREATE TABLE IF NOT EXISTS master_wallet (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            balance INTEGER NOT NULL DEFAULT 0
        );
    )";
    executeSQL(masterWalletTable);

    // Ensure master wallet row exists
    std::string insertMaster = R"(
        INSERT OR IGNORE INTO master_wallet (id, balance) VALUES (1, 0);
    )";
    executeSQL(insertMaster);

    // User wallet table
    std::string userWalletTable = R"(
        CREATE TABLE IF NOT EXISTS user_wallet (
            user_id INTEGER PRIMARY KEY,
            balance INTEGER NOT NULL DEFAULT 0
        );
    )";
    executeSQL(userWalletTable);
    
    // Transaction history table
    std::string transactionHistoryTable = R"(
        CREATE TABLE IF NOT EXISTS transaction_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            from_id INTEGER NOT NULL,
            to_id INTEGER NOT NULL,
            points INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    )";
    executeSQL(transactionHistoryTable);
}

std::string WalletManager::getUserRole(int userId) {
    std::string role;
    std::string sql = "SELECT role FROM users WHERE id = ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, userId);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char* text = sqlite3_column_text(stmt, 0);
            if (text) role = reinterpret_cast<const char*>(text);
        }
    }
    sqlite3_finalize(stmt);
    return role;
}

bool WalletManager::isUserExists(int userId) {
    std::string sql = "SELECT 1 FROM users WHERE id = ?;";
    sqlite3_stmt* stmt = nullptr;
    bool exists = false;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, userId);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            exists = true;
        }
    }
    sqlite3_finalize(stmt);
    return exists;
}

std::string WalletManager::getUserEmailById(int userId) {
    // Special IDs
    if (userId == 0) return "System";
    if (userId == -1) return "Master Wallet";
    
    // Regular user IDs
    std::string email;
    std::string sql = "SELECT email FROM users WHERE id = ?;";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, userId);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char* text = sqlite3_column_text(stmt, 0);
            if (text) email = reinterpret_cast<const char*>(text);
        }
    }
    sqlite3_finalize(stmt);
    return email;
}

bool WalletManager::recordTransaction(const std::string& type, int fromId, int toId, int points) {
    std::string sql = R"(
        INSERT INTO transaction_history (type, from_id, to_id, points)
        VALUES (?, ?, ?, ?);
    )";
    
    sqlite3_stmt* stmt = nullptr;
    bool success = false;
    
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, type.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 2, fromId);
        sqlite3_bind_int(stmt, 3, toId);
        sqlite3_bind_int(stmt, 4, points);
        
        if (sqlite3_step(stmt) == SQLITE_DONE) {
            success = true;
        }
    }
    
    sqlite3_finalize(stmt);
    return success;
}

bool WalletManager::topUpMasterWallet(int adminUserId, int points) {
    if (getUserRole(adminUserId) != "ADMIN" || points <= 0) return false;
    
    executeSQL("BEGIN TRANSACTION;");
    try {
        std::string sql = "UPDATE master_wallet SET balance = balance + ? WHERE id = 1;";
        sqlite3_stmt* stmt = nullptr;
        bool success = false;
        
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, points);
            if (sqlite3_step(stmt) == SQLITE_DONE) {
                success = true;
            }
        }
        sqlite3_finalize(stmt);
        
        // Record transaction: 0 = system, -1 = master wallet
        if (success) {
            success = recordTransaction("TOPUP", 0, -1, points);
        }
        
        if (success) {
            executeSQL("COMMIT;");
            return true;
        } else {
            executeSQL("ROLLBACK;");
            return false;
        }
    } catch (...) {
        executeSQL("ROLLBACK;");
        return false;
    }
}

bool WalletManager::sendPointsFromMasterToUser(int adminUserId, int toUserId, int points) {
    if (getUserRole(adminUserId) != "ADMIN" || points <= 0 || !isUserExists(toUserId)) return false;

    std::string recipientRole = getUserRole(toUserId);
    if (recipientRole != "USER") {
        // Admin cannot send points from master to another admin
        return false;
    }

    // Begin transaction
    executeSQL("BEGIN TRANSACTION;");
    try {
        // Check master wallet balance
        int masterBalance = getMasterWalletBalance();
        if (masterBalance < points) {
            executeSQL("ROLLBACK;");
            return false;
        }

        // Deduct from master
        std::string deductSql = "UPDATE master_wallet SET balance = balance - ? WHERE id = 1;";
        sqlite3_stmt* deductStmt = nullptr;
        sqlite3_prepare_v2(db, deductSql.c_str(), -1, &deductStmt, nullptr);
        sqlite3_bind_int(deductStmt, 1, points);
        if (sqlite3_step(deductStmt) != SQLITE_DONE) {
            sqlite3_finalize(deductStmt);
            executeSQL("ROLLBACK;");
            return false;
        }
        sqlite3_finalize(deductStmt);

        // Add to user wallet (create if not exists)
        std::string insertUserWallet = "INSERT OR IGNORE INTO user_wallet (user_id, balance) VALUES (?, 0);";
        sqlite3_stmt* insertStmt = nullptr;
        sqlite3_prepare_v2(db, insertUserWallet.c_str(), -1, &insertStmt, nullptr);
        sqlite3_bind_int(insertStmt, 1, toUserId);
        sqlite3_step(insertStmt);
        sqlite3_finalize(insertStmt);

        std::string addSql = "UPDATE user_wallet SET balance = balance + ? WHERE user_id = ?;";
        sqlite3_stmt* addStmt = nullptr;
        sqlite3_prepare_v2(db, addSql.c_str(), -1, &addStmt, nullptr);
        sqlite3_bind_int(addStmt, 1, points);
        sqlite3_bind_int(addStmt, 2, toUserId);
        if (sqlite3_step(addStmt) != SQLITE_DONE) {
            sqlite3_finalize(addStmt);
            executeSQL("ROLLBACK;");
            return false;
        }
        sqlite3_finalize(addStmt);

        // Record transaction: -1 = master wallet, toUserId = receiving user
        bool transactionRecorded = recordTransaction("MASTER_TO_USER", -1, toUserId, points);
        if (!transactionRecorded) {
            executeSQL("ROLLBACK;");
            return false;
        }
        
        executeSQL("COMMIT;");
        return true;
    } catch (...) {
        executeSQL("ROLLBACK;");
        return false;
    }
}

bool WalletManager::sendPointsToUser(int fromUserId, int toUserId, int points) {
    if (fromUserId == toUserId || points <= 0 || !isUserExists(fromUserId) || !isUserExists(toUserId)) return false;

    std::string recipientRole = getUserRole(toUserId);
    if (recipientRole == "ADMIN") {
        // User can only send to another user, not to admin
        return false;
    }

    // Begin transaction
    executeSQL("BEGIN TRANSACTION;");
    try {
        // Ensure both wallets exist
        std::string insertFrom = "INSERT OR IGNORE INTO user_wallet (user_id, balance) VALUES (?, 0);";
        sqlite3_stmt* stmtFrom = nullptr;
        sqlite3_prepare_v2(db, insertFrom.c_str(), -1, &stmtFrom, nullptr);
        sqlite3_bind_int(stmtFrom, 1, fromUserId);
        sqlite3_step(stmtFrom);
        sqlite3_finalize(stmtFrom);

        std::string insertTo = "INSERT OR IGNORE INTO user_wallet (user_id, balance) VALUES (?, 0);";
        sqlite3_stmt* stmtTo = nullptr;
        sqlite3_prepare_v2(db, insertTo.c_str(), -1, &stmtTo, nullptr);
        sqlite3_bind_int(stmtTo, 1, toUserId);
        sqlite3_step(stmtTo);
        sqlite3_finalize(stmtTo);

        // Check sender balance
        int senderBalance = getUserWalletBalance(fromUserId);
        if (senderBalance < points) {
            executeSQL("ROLLBACK;");
            return false;
        }

        // Deduct from sender
        std::string deductSql = "UPDATE user_wallet SET balance = balance - ? WHERE user_id = ?;";
        sqlite3_stmt* deductStmt = nullptr;
        sqlite3_prepare_v2(db, deductSql.c_str(), -1, &deductStmt, nullptr);
        sqlite3_bind_int(deductStmt, 1, points);
        sqlite3_bind_int(deductStmt, 2, fromUserId);
        if (sqlite3_step(deductStmt) != SQLITE_DONE) {
            sqlite3_finalize(deductStmt);
            executeSQL("ROLLBACK;");
            return false;
        }
        sqlite3_finalize(deductStmt);

        // Add to receiver
        std::string addSql = "UPDATE user_wallet SET balance = balance + ? WHERE user_id = ?;";
        sqlite3_stmt* addStmt = nullptr;
        sqlite3_prepare_v2(db, addSql.c_str(), -1, &addStmt, nullptr);
        sqlite3_bind_int(addStmt, 1, points);
        sqlite3_bind_int(addStmt, 2, toUserId);
        if (sqlite3_step(addStmt) != SQLITE_DONE) {
            sqlite3_finalize(addStmt);
            executeSQL("ROLLBACK;");
            return false;
        }
        sqlite3_finalize(addStmt);
        
        // Record transaction from fromUserId to toUserId
        bool transactionRecorded = recordTransaction("USER_TO_USER", fromUserId, toUserId, points);
        if (!transactionRecorded) {
            executeSQL("ROLLBACK;");
            return false;
        }

        executeSQL("COMMIT;");
        return true;
    } catch (...) {
        executeSQL("ROLLBACK;");
        return false;
    }
}

int WalletManager::getMasterWalletBalance() {
    int balance = 0;
    std::string sql = "SELECT balance FROM master_wallet WHERE id = 1;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            balance = sqlite3_column_int(stmt, 0);
        }
    }
    sqlite3_finalize(stmt);
    return balance;
}

int WalletManager::getUserWalletBalance(int userId) {
    int balance = 0;
    std::string sql = "SELECT balance FROM user_wallet WHERE user_id = ?;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, userId);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            balance = sqlite3_column_int(stmt, 0);
        }
    }
    sqlite3_finalize(stmt);
    return balance;
}

int WalletManager::getUserIdByEmail(const std::string& email) {
    int userId = -1;
    std::string sql = "SELECT id FROM users WHERE email = ?;";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            userId = sqlite3_column_int(stmt, 0);
        }
    }
    sqlite3_finalize(stmt);
    return userId;
}

int WalletManager::getUserWalletBalanceByEmail(const std::string& email) {
    int userId = getUserIdByEmail(email);
    if (userId <= 0) {
        return -1; // User not found
    }
    
    return getUserWalletBalance(userId);
}

bool WalletManager::sendPointsFromMasterToUserByEmail(int adminUserId, const std::string& toUserEmail, int points) {
    int toUserId = getUserIdByEmail(toUserEmail);
    
    if (toUserId <= 0) {
        return false;
    }
    
    return sendPointsFromMasterToUser(adminUserId, toUserId, points);
}

bool WalletManager::sendPointsToUserByEmail(int fromUserId, const std::string& toUserEmail, int points) {
    int toUserId = getUserIdByEmail(toUserEmail);
    
    if (toUserId <= 0) {
        return false;
    }
    
    return sendPointsToUser(fromUserId, toUserId, points);
}

std::vector<TransactionRecord> WalletManager::getMasterWalletHistory(int adminUserId) {
    std::vector<TransactionRecord> history;
    
    // Check if the requestor is an admin
    if (getUserRole(adminUserId) != "ADMIN") {
        return history; // Return empty if not admin
    }
    
    std::string sql = R"(
        SELECT id, type, from_id, to_id, points, datetime(timestamp, 'localtime') as timestamp
        FROM transaction_history
        WHERE from_id = -1 OR to_id = -1
        ORDER BY timestamp DESC;
    )";
    
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            TransactionRecord record;
            record.id = sqlite3_column_int(stmt, 0);
            
            const unsigned char* typeText = sqlite3_column_text(stmt, 1);
            if (typeText) record.type = reinterpret_cast<const char*>(typeText);
            
            record.fromId = sqlite3_column_int(stmt, 2);
            record.toId = sqlite3_column_int(stmt, 3);
            record.points = sqlite3_column_int(stmt, 4);
            
            const unsigned char* timestampText = sqlite3_column_text(stmt, 5);
            if (timestampText) record.timestamp = reinterpret_cast<const char*>(timestampText);
            
            // Resolve names
            record.fromName = getUserEmailById(record.fromId);
            record.toName = getUserEmailById(record.toId);
            
            history.push_back(record);
        }
    }
    
    sqlite3_finalize(stmt);
    return history;
}

std::vector<TransactionRecord> WalletManager::getUserWalletHistory(int requestorUserId, int targetUserId) {
    std::vector<TransactionRecord> history;
    
    // Check if the requestor is authorized (admin or self)
    std::string role = getUserRole(requestorUserId);
    if (role != "ADMIN" && requestorUserId != targetUserId) {
        return history; // Return empty if not authorized
    }
    
    std::string sql = R"(
        SELECT id, type, from_id, to_id, points, datetime(timestamp, 'localtime') as timestamp
        FROM transaction_history
        WHERE from_id = ? OR to_id = ?
        ORDER BY timestamp DESC;
    )";
    
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_int(stmt, 1, targetUserId);
        sqlite3_bind_int(stmt, 2, targetUserId);
        
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            TransactionRecord record;
            record.id = sqlite3_column_int(stmt, 0);
            
            const unsigned char* typeText = sqlite3_column_text(stmt, 1);
            if (typeText) record.type = reinterpret_cast<const char*>(typeText);
            
            record.fromId = sqlite3_column_int(stmt, 2);
            record.toId = sqlite3_column_int(stmt, 3);
            record.points = sqlite3_column_int(stmt, 4);
            
            const unsigned char* timestampText = sqlite3_column_text(stmt, 5);
            if (timestampText) record.timestamp = reinterpret_cast<const char*>(timestampText);
            
            // Resolve names
            record.fromName = getUserEmailById(record.fromId);
            record.toName = getUserEmailById(record.toId);
            
            history.push_back(record);
        }
    }
    
    sqlite3_finalize(stmt);
    return history;
}

std::vector<TransactionRecord> WalletManager::getUserWalletHistoryByEmail(int requestorUserId, const std::string& targetEmail) {
    int targetUserId = getUserIdByEmail(targetEmail);
    
    if (targetUserId <= 0) {
        return std::vector<TransactionRecord>(); // Return empty if user not found
    }
    
    return getUserWalletHistory(requestorUserId, targetUserId);
}