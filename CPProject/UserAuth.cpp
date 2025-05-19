#include "UserAuth.h"
#include "CredentialReader.h"
#include <iostream>
#include <random>
#include <string>
#include <functional>
#include <sstream>
#include <iomanip>

// Generate a random salt
std::string UserAuth::generateSalt(size_t length) {
	static const char charset[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dist(0, sizeof(charset) - 2);

	std::string salt;
	salt.reserve(length);

	for (size_t i = 0; i < length; ++i) {
		salt += charset[dist(gen)];
	}

	return salt;
}

// Generate a random password
std::string UserAuth::generateRandomPassword(size_t length) {
	return generateSalt(length);
}

std::string UserAuth::hashPassword(const std::string& password, const std::string& salt) {
	// Combine password with salt
	std::string combined = password + salt;

	// Use std::hash to create a hash
	std::hash<std::string> hasher;
	size_t hashValue = hasher(combined);

	// Convert hash to string (hexadecimal format)
	std::stringstream ss;
	ss << std::hex << std::setfill('0') << std::setw(16) << hashValue;

	// For additional security, apply multiple iterations
	std::string result = ss.str();
	for (int i = 0; i < 10000; i++) {
		// Re-hash the result with the salt each iteration
		result += salt;
		hashValue = hasher(result);
		ss.str("");  // Clear the stringstream
		ss << std::hex << std::setfill('0') << std::setw(16) << hashValue;
		result = ss.str();
	}

	return result;
}

bool UserAuth::insertUser(const std::string& email, const std::string& hashPw,
	const std::string& salt, const std::string& role,
	const std::string& realName, const std::string& nationality,
	bool shouldChangePassword) {
	std::string sql = "INSERT INTO users (email, password, salt, role, real_name, nationality, should_change_password) VALUES (?, ?, ?, ?, ?, ?, ?);";
	sqlite3_stmt* stmt;

	if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
		std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
		return false;
	}

	sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, hashPw.c_str(), -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, salt.c_str(), -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 4, role.c_str(), -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 5, realName.c_str(), -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 6, nationality.c_str(), -1, SQLITE_STATIC);
	sqlite3_bind_int(stmt, 7, shouldChangePassword ? 1 : 0);

	if (sqlite3_step(stmt) != SQLITE_DONE) {
		std::cerr << "Failed to insert user: " << sqlite3_errmsg(db) << std::endl;
		sqlite3_finalize(stmt);
		return false;
	}

	sqlite3_finalize(stmt);
	return true;
}


bool UserAuth::verifyPassword(const std::string& email, const std::string& password) {
	std::string sql = "SELECT password, salt FROM users WHERE email = ?;";
	sqlite3_stmt* stmt;

	if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
		std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
		return false;
	}

	sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_STATIC);

	if (sqlite3_step(stmt) != SQLITE_ROW) {
		std::cerr << "User not found or invalid credentials." << std::endl;
		sqlite3_finalize(stmt);
		return false;
	}

	std::string storedHash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
	std::string storedSalt = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
	sqlite3_finalize(stmt);

	std::string hashedPassword = hashPassword(password, storedSalt);
	return hashedPassword == storedHash;
}

bool UserAuth::getUserInfo(const std::string& email, User& userInfo) {
	std::string sql = "SELECT id, email, role, real_name, nationality, should_change_password FROM users WHERE email = ?;";
	sqlite3_stmt* stmt;

	if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
		std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
		return false;
	}

	sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_STATIC);

	if (sqlite3_step(stmt) == SQLITE_ROW) {
		userInfo.id = sqlite3_column_int(stmt, 0);
		userInfo.email = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
		userInfo.role = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
		userInfo.shouldChangePassword = sqlite3_column_int(stmt, 5) == 1;

		// Get optional fields if available
		const unsigned char* realNameText = sqlite3_column_text(stmt, 3);
		if (realNameText) {
			userInfo.realName = reinterpret_cast<const char*>(realNameText);
		}
		else {
			userInfo.realName = OPTONAL_FIELD_VAL;
		}
		const unsigned char* nationalityText = sqlite3_column_text(stmt, 4);
		if (nationalityText) {
			userInfo.nationality = reinterpret_cast<const char*>(nationalityText);
		}
		else {
			userInfo.nationality = OPTONAL_FIELD_VAL;
		}

		sqlite3_finalize(stmt);
		return true;
	}

	sqlite3_finalize(stmt);
	return false;
}

bool UserAuth::verifyUserOTP(const std::string& email, const std::string& otp) {
	if (!otpManager.verifyOTP(email, otp)) {
		std::cerr << "Invalid OTP." << std::endl;
		return false;
	}
	return true;
}

void UserAuth::executeSQL(const std::string& sql) {
	char* errMsg = nullptr;
	if (sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errMsg) != SQLITE_OK) {
		std::cerr << "SQL error: " << errMsg << std::endl;
		sqlite3_free(errMsg);
	}
}

UserAuth::UserAuth(sqlite3* dbConnection) : db(dbConnection) {
	std::string createTableSQL = R"(
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('ADMIN', 'USER')),
            real_name TEXT DEFAULT 'No information',
            nationality TEXT DEFAULT 'No information',
            should_change_password INTEGER DEFAULT 0
        );
    )";
	executeSQL(createTableSQL);

	// Read credentials from file
	std::unordered_map<std::string, std::pair<std::string, std::string>> credentials;
	if (!CredentialReader::readCredentials("credentials.json", credentials)) {
		std::cerr << "Failed to read credentials. Exiting..." << std::endl;
		exit(1);
	}

	// Configure EmailSender
	auto emailIt = credentials.find("2fa-mail");
	if (emailIt != credentials.end()) {
		const std::string& emailUsername = emailIt->second.first;
		const std::string& emailPassword = emailIt->second.second;
		emailSender = EmailSender(emailUsername, emailPassword);
	}
	else {
		std::cerr << "Warning: Email credentials not found. OTP functionality may not work." << std::endl;
	}

	// Check if we need to add admin accounts
	std::string checkAdminSQL = "SELECT COUNT(*) FROM users WHERE role = 'ADMIN';";
	sqlite3_stmt* stmt;
	if (sqlite3_prepare_v2(db, checkAdminSQL.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
		if (sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_int(stmt, 0) == 0) {
			// No admins exist yet, add them from credentials
			for (const auto& [key, value] : credentials) {
				// Only process entries marked as admin
				if (key.substr(0, 6) == "admin:" || key == "admin") {
					const std::string& adminEmail = value.first;
					const std::string& adminPassword = value.second;

					std::string salt = generateSalt(16);
					std::string hashedPassword = hashPassword(adminPassword, salt);

					insertUser(adminEmail, hashedPassword, salt, "ADMIN", OPTONAL_FIELD_VAL, OPTONAL_FIELD_VAL);
				}
			}
		}
		sqlite3_finalize(stmt);
	}
}



UserAuth::~UserAuth() {
}

bool UserAuth::initiateSignUp(const std::string& email, const std::string& password) {
	// Check if user already exists
	if (isUserExists(email)) {
		std::cerr << "User with email " << email << " already exists." << std::endl;
		return false;
	}

	// Generate a salt and hash the password
	std::string salt = generateSalt(16);
	std::string hashedPassword = hashPassword(password, salt);

	// Store the hashed password temporarily
	pendingSignups[email] = { hashedPassword, salt };

	// Generate and send OTP
	std::string otp = otpManager.generateOTP(email);
	std::string subject = "Complete Your Sign-Up";
	std::string body = "Your OTP for sign-up is: " + otp + "\r\n\r\nThis code will expire in 5 minutes.";
	if (!emailSender.sendEmail(email, subject, body)) {
		std::cerr << "Failed to send OTP email." << std::endl;
		return false;
	}

	return true;
}

bool UserAuth::completeSignUp(const std::string& email, const std::string& otp, User& userInfo) {
	// Verify the OTP
	if (!verifyUserOTP(email, otp)) {
		std::cerr << "Sign-up failed." << std::endl;
		return false;
	}

	// Retrieve the hashed password
	auto it = pendingSignups.find(email);
	if (it == pendingSignups.end()) {
		std::cerr << "No pending sign-up found for this email." << std::endl;
		return false;
	}
	std::string hashedPassword = it->second.password;
	std::string salt = it->second.salt;

	// Insert the user into the database with optional fields
	if (!insertUser(email, hashedPassword, salt, "USER", userInfo.realName, userInfo.nationality)) {
		return false;
	}

	pendingSignups.erase(it);

	// Retrieve the newly created user information
	return getUserInfo(email, userInfo);
}

bool UserAuth::initiateLogin(const std::string& email, const std::string& password) {
	// Verify the user's password
	if (!verifyPassword(email, password)) {
		std::cerr << "Invalid email or password." << std::endl;
		return false;
	}

	// Generate and send OTP
	std::string otp = otpManager.generateOTP(email);
	std::string subject = "Your Login OTP";
	std::string body = "Your OTP for login is: " + otp + "\r\n\r\nThis code will expire in 5 minutes.";
	if (!emailSender.sendEmail(email, subject, body)) {
		std::cerr << "Failed to send OTP email." << std::endl;
		return false;
	}

	return true;
}

bool UserAuth::completeLogin(const std::string& email, const std::string& otp, User& userInfo) {
	// Verify the OTP
	if (!verifyUserOTP(email, otp)) {
		std::cerr << "Login failed." << std::endl;
		return false;
	}

	// Get and return user information
	if (!getUserInfo(email, userInfo)) {
		std::cerr << "User not found in database after OTP verification." << std::endl;
		return false;
	}

	return true;
}

bool UserAuth::createUserByAdmin(const std::string& email) {
	// Check if user already exists
	if (isUserExists(email)) {
		std::cerr << "User with email " << email << " already exists." << std::endl;
		return false;
	}

	// Generate a random password
	std::string randomPassword = generateRandomPassword(12);

	// Generate a salt and hash the password
	std::string salt = generateSalt(16);
	std::string hashedPassword = hashPassword(randomPassword, salt);

	// Generate and send OTP for verification
	std::string otp = otpManager.generateOTP(email);
	std::string subject = "Your Account Has Been Created";
	std::string body = "An administrator has created an account for you.\r\n\r\n"
		"Your temporary password is: " + randomPassword + "\r\n\r\n"
		"You will be required to change this password when you first log in.\r\n\r\n"
		"Your OTP code is: " + otp + "\r\n\r\n"
		"This code will expire in 5 minutes.";

	if (!emailSender.sendEmail(email, subject, body)) {
		std::cerr << "Failed to send OTP email." << std::endl;
		return false;
	}

	// Store the data for later completion
	pendingSignups[email] = { hashedPassword, salt };

	std::cout << "User account initiated for " << email << " with password: " << randomPassword << std::endl;
	return true;
}

bool UserAuth::completeCreateUserByAdmin(const std::string& email, const std::string& otp, User& userInfo) {
	// Verify the OTP
	if (!verifyUserOTP(email, otp)) {
		std::cerr << "User creation failed." << std::endl;
		return false;
	}

	// Retrieve the hashed password
	auto it = pendingSignups.find(email);
	if (it == pendingSignups.end()) {
		std::cerr << "No pending sign-up found for this email." << std::endl;
		return false;
	}
	std::string hashedPassword = it->second.password;
	std::string salt = it->second.salt;

	// Insert the user with should_change_password set to true
	if (!insertUser(email, hashedPassword, salt, "USER", OPTONAL_FIELD_VAL, OPTONAL_FIELD_VAL, true)) {
		return false;
	}

	pendingSignups.erase(it);

	// Retrieve the newly created user information
	return getUserInfo(email, userInfo);
}

bool UserAuth::changePassword(const std::string& email, const std::string& currentPassword, const std::string& newPassword) {
	// First verify the current password
	if (!verifyPassword(email, currentPassword)) {
		return false;
	}

	// Generate a new salt for better security
	std::string newSalt = generateSalt(16);
	std::string hashedNewPassword = hashPassword(newPassword, newSalt);

	// Update the password in the database
	std::string sql = "UPDATE users SET password = ?, salt = ?, should_change_password = 0 WHERE email = ?;";
	sqlite3_stmt* stmt;

	if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
		std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
		return false;
	}

	sqlite3_bind_text(stmt, 1, hashedNewPassword.c_str(), -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, newSalt.c_str(), -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, email.c_str(), -1, SQLITE_STATIC);

	if (sqlite3_step(stmt) != SQLITE_DONE) {
		std::cerr << "Failed to update password: " << sqlite3_errmsg(db) << std::endl;
		sqlite3_finalize(stmt);
		return false;
	}

	sqlite3_finalize(stmt);
	return true;
}

bool UserAuth::isUserExists(const std::string& email) {
	std::string sql = "SELECT COUNT(*) FROM users WHERE email = ?;";
	sqlite3_stmt* stmt;

	if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
		std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
		return false;
	}

	sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_STATIC);

	if (sqlite3_step(stmt) == SQLITE_ROW) {
		int count = sqlite3_column_int(stmt, 0);
		sqlite3_finalize(stmt);
		return count > 0;
	}

	sqlite3_finalize(stmt);
	return false;
}

bool UserAuth::updateUserInfo(int userId, const std::string& realName, const std::string& nationality) {
	// Check if user exists
	std::string checkUserSQL = "SELECT COUNT(*) FROM users WHERE id = ?;";
	sqlite3_stmt* checkStmt;

	if (sqlite3_prepare_v2(db, checkUserSQL.c_str(), -1, &checkStmt, nullptr) != SQLITE_OK) {
		std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
		return false;
	}

	sqlite3_bind_int(checkStmt, 1, userId);

	if (sqlite3_step(checkStmt) != SQLITE_ROW || sqlite3_column_int(checkStmt, 0) == 0) {
		std::cerr << "User with ID " << userId << " does not exist." << std::endl;
		sqlite3_finalize(checkStmt);
		return false;
	}
	sqlite3_finalize(checkStmt);

	// Update user information in the database
	std::string sql = "UPDATE users SET real_name = ?, nationality = ? WHERE id = ?;";
	sqlite3_stmt* stmt;

	if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
		std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
		return false;
	}

	std::string realNameValue = realName.empty() ? OPTONAL_FIELD_VAL : realName;
	std::string nationalityValue = nationality.empty() ? OPTONAL_FIELD_VAL : nationality;

	sqlite3_bind_text(stmt, 1, realNameValue.c_str(), -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, nationalityValue.c_str(), -1, SQLITE_STATIC);
	sqlite3_bind_int(stmt, 3, userId);

	if (sqlite3_step(stmt) != SQLITE_DONE) {
		std::cerr << "Failed to update user information: " << sqlite3_errmsg(db) << std::endl;
		sqlite3_finalize(stmt);
		return false;
	}

	sqlite3_finalize(stmt);
	std::cout << "User information updated successfully." << std::endl;
	return true;
}
