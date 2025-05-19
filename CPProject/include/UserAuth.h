#pragma once

#include <string>
#include <unordered_map>
#include "sqlite3.h"
#include "EmailSender.h"
#include "OTPManager.h"

constexpr auto OPTONAL_FIELD_VAL = "No information";

struct User {
    int id;
    std::string email;
    std::string role;
    std::string realName = OPTONAL_FIELD_VAL;
    std::string nationality = OPTONAL_FIELD_VAL;
    bool shouldChangePassword = false;
};

struct PendingSignup {
    std::string password;
    std::string salt;
};

class UserAuth {
private:
    EmailSender emailSender;
    OTPManager otpManager;

    std::unordered_map<std::string, PendingSignup> pendingSignups;

    sqlite3* db;
    
    void executeSQL(const std::string& sql);
    std::string hashPassword(const std::string& password, const std::string& salt);
    std::string generateSalt(size_t length = 16);
    std::string generateRandomPassword(size_t length);

    bool insertUser(const std::string& email, const std::string& hashPw, const std::string& salt, const std::string& role, const std::string& realName = OPTONAL_FIELD_VAL, const std::string& nationality = OPTONAL_FIELD_VAL, bool shouldChangePassword = false);
    bool verifyPassword(const std::string& email, const std::string& password);
    bool getUserInfo(const std::string& email, User& userInfo);
    bool verifyUserOTP(const std::string& email, const std::string& otp);
    bool isUserExists(const std::string& email);

public:
    UserAuth(sqlite3* dbConnection);
    
    ~UserAuth();

    bool initiateSignUp(const std::string& email, const std::string& password);
    bool completeSignUp(const std::string& email, const std::string& otp, User& userInfo);
    bool initiateLogin(const std::string& email, const std::string& password);
    bool completeLogin(const std::string& email, const std::string& otp, User& userInfo);

    bool createUserByAdmin(const std::string& email);
    bool completeCreateUserByAdmin(const std::string& email, const std::string& otp, User& userInfo);

    bool changePassword(const std::string& email, const std::string& currentPassword, const std::string& newPassword);
    bool updateUserInfo(int userId, const std::string& realName, const std::string& nationality);
};