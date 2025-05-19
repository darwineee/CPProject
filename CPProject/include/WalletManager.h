#pragma once

#include <string>
#include <vector>
#include "sqlite3.h"

struct TransactionRecord {
    int id;
    std::string type;        // "TOPUP", "MASTER_TO_USER", "USER_TO_USER"
    int fromId;              // 0 for system topup, -1 for master wallet, positive user id for user transfers
    int toId;                // -1 for master wallet or positive user id
    int points;
    std::string timestamp;
    std::string fromName;    // "System", "Master Wallet", or user email
    std::string toName;      // "Master Wallet" or user email
};

class WalletManager {
private:
    sqlite3* db; // Connection owned by the main function

    // Helper to execute SQL and handle errors
    void executeSQL(const std::string& sql);

    // Helper to get user role by userId
    std::string getUserRole(int userId);

    // Helper to check if user exists
    bool isUserExists(int userId);

    // Initialize wallet tables if not exist
    void initializeWalletTables();

    // Helper to get user ID from email
    int getUserIdByEmail(const std::string& email);
    
    // Helper to get user email from ID
    std::string getUserEmailById(int userId);
    
    // Helper to record a transaction
    bool recordTransaction(const std::string& type, int fromId, int toId, int points);

public:
    WalletManager(sqlite3* dbConnection);
    
    ~WalletManager();

    // Admin: Top up master wallet
    bool topUpMasterWallet(int adminUserId, int points);

    // Admin: Send points from master wallet to user
    bool sendPointsFromMasterToUser(int adminUserId, int toUserId, int points);

    // Admin: Send points from master wallet to user (by email)
    bool sendPointsFromMasterToUserByEmail(int adminUserId, const std::string& toUserEmail, int points);

    // User: Send points to another user
    bool sendPointsToUser(int fromUserId, int toUserId, int points);

    // User: Send points to another user
    bool sendPointsToUserByEmail(int fromUserId, const std::string& toUserEmail, int points);

    // Get balance of master wallet
    int getMasterWalletBalance();

    // Get balance of user wallet
    int getUserWalletBalance(int userId);
    
    // New method to get wallet balance by email
    int getUserWalletBalanceByEmail(const std::string& email);
    
    // Get transaction history for the master wallet (admin only)
    std::vector<TransactionRecord> getMasterWalletHistory(int adminUserId);
    
    // Get transaction history for a specific user wallet (admin or self)
    std::vector<TransactionRecord> getUserWalletHistory(int requestorUserId, int targetUserId);
    
    // Get transaction history for a specific user wallet by email (admin or self)
    std::vector<TransactionRecord> getUserWalletHistoryByEmail(int requestorUserId, const std::string& targetEmail);
};