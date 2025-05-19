#include "UserAuth.h"
#include "WalletManager.h"
#include "sqlite3.h"
#include <iostream>
#include <optional>
#include <string>  

static std::optional<User> currentUser;

static void displayAuthMenu();
static void handleSignUp(UserAuth& auth);
static void handleLogin(UserAuth& auth, WalletManager& walletManager);
static void handleLogout();
static void handleViewProfile(const User& user);
static void handleChangePassword(UserAuth& auth, User& user);
static void handleUpdateProfile(UserAuth& auth, User& user);
static void showUserMenu(UserAuth& auth, WalletManager& walletManager, User& user);
static void showAdminMenu(UserAuth& auth, WalletManager& walletManager, User& user);
static void handleAdminCreateUser(UserAuth& auth);

static void handleTopUpMasterWallet(WalletManager& walletManager, const User& admin);
static void handleSendPointsFromMaster(WalletManager& walletManager, const User& admin);
static void handleSendPointsToUser(WalletManager& walletManager, const User& user);
static void handleViewMasterWalletBalanceAndHistory(WalletManager& walletManager, const User& admin);
static void handleViewOwnWalletBalanceAndHistory(WalletManager& walletManager, const User& user);

static void displayTransactionRecord(const TransactionRecord& record) {
    std::string direction;
    std::string impact;
    
    if (record.fromId == -1 && record.toId > 0) {
        // Master wallet to user
        direction = "from Master Wallet to " + record.toName;
        // Change here: when user is viewing their own history and they're the recipient
        if (currentUser && currentUser->id == record.toId) {
            impact = "+"; // User received points, so it's positive for them
        } else {
            impact = "-"; // For admin view, it shows as negative (points leaving master wallet)
        }
    } else if (record.fromId > 0 && record.toId == -1) {
        // User to Master wallet (not likely in current implementation but we may need it in the future, like reclaim the points)
        direction = "from " + record.fromName + " to Master Wallet";
        impact = "+";
    } else if (record.fromId == 0 && record.toId == -1) {
        // System top up to master
        direction = "from System to Master Wallet";
        impact = "+";
    } else if (record.fromId > 0 && record.toId > 0) {
        // User to user
        direction = "from " + record.fromName + " to " + record.toName;
        if (currentUser && currentUser->id == record.fromId) impact = "-";
        else if (currentUser && currentUser->id == record.toId) impact = "+";
        else impact = "";  // For admin viewing others' transactions
    }
    
    std::cout << record.timestamp << " | " 
              << record.type << " | " 
              << direction << " | "
              << impact << record.points << " points" 
              << std::endl;
}

static void displayAuthMenu() {
    std::cout << "\n========== Authentication ==========\n";
    std::cout << "1. Sign Up\n";
    std::cout << "2. Login\n";
    std::cout << "3. Exit\n";
    std::cout << "Enter your choice: ";
}

static void handleSignUp(UserAuth& auth) {
    std::string email, password, otp, realName, nationality;

    std::cout << "Enter email: ";
    std::cin >> email;
    std::cout << "Enter password: ";
    std::cin >> password;

    std::cout << "Enter your real name (optional): ";
    std::cin.ignore();
    std::getline(std::cin, realName);
    if (realName.empty()) {
        realName = "No information";
    }

    std::cout << "Enter your nationality (optional): ";
    std::getline(std::cin, nationality);
    if (nationality.empty()) {
        nationality = "No information";
    }

    if (auth.initiateSignUp(email, password)) {
        std::cout << "OTP sent to your email. Please check and enter the OTP: ";
        std::cin >> otp;

        User userInfo;
        userInfo.realName = realName;
        userInfo.nationality = nationality;

        if (auth.completeSignUp(email, otp, userInfo)) {
            std::cout << "Sign-up successful!" << std::endl;
        }
        else {
            std::cout << "OTP verification failed. Please try again." << std::endl;
        }
    }
    else {
        std::cout << "Failed to initiate sign-up." << std::endl;
    }
}

static void handleLogin(UserAuth& auth, WalletManager& walletManager) {
    std::string email, password, otp;

    std::cout << "Enter email: ";
    std::cin >> email;
    std::cout << "Enter password: ";
    std::cin >> password;

    if (auth.initiateLogin(email, password)) {
        std::cout << "OTP sent to your email. Please check and enter the OTP: ";
        std::cin >> otp;

        User userInfo;
        if (auth.completeLogin(email, otp, userInfo)) {
            std::cout << "Login successful!" << std::endl;
            currentUser = userInfo;

            if (userInfo.shouldChangePassword) {
                std::cout << "Your account is created by ADMIN. You must change your password before proceeding." << std::endl;
                handleChangePassword(auth, userInfo);
            }

            if (userInfo.role == "ADMIN") {
                showAdminMenu(auth, walletManager, userInfo);
            }
            else {
                showUserMenu(auth, walletManager, userInfo);
            }
        }
        else {
            std::cout << "OTP verification failed. Please try again." << std::endl;
        }
    }
    else {
        std::cout << "Invalid email or password." << std::endl;
    }
}

static void handleLogout() {
    if (currentUser.has_value()) {
        currentUser = std::nullopt;
        std::cout << "Logout successful!" << std::endl;
    }
    else {
        std::cout << "No user is currently logged in." << std::endl;
    }
}

static void handleViewProfile(const User& user) {
    std::cout << "\n========== User Profile ==========\n";
    std::cout << "User ID: " << user.id << std::endl;
    std::cout << "Email: " << user.email << std::endl;
    std::cout << "Role: " << user.role << std::endl;
    std::cout << "Real Name: " << user.realName << std::endl;
    std::cout << "Nationality: " << user.nationality << std::endl;
}

static void handleUpdateProfile(UserAuth& auth, User& user) {
    std::string realName, nationality;

    std::cout << "\n========== Update Profile ==========\n";
    std::cout << "Current Real Name: " << user.realName << std::endl;
    std::cout << "Current Nationality: " << user.nationality << std::endl;

    std::cout << "\nEnter new real name (leave empty to keep current): ";
    std::cin.ignore();
    std::getline(std::cin, realName);

    std::cout << "Enter new nationality (leave empty to keep current): ";
    std::getline(std::cin, nationality);

    // If both fields are empty, no need to update
    if (realName.empty() && nationality.empty()) {
        return;
    }

    if (realName.empty()) {
        realName = user.realName;
    }

    if (nationality.empty()) {
        nationality = user.nationality;
    }

    if (auth.updateUserInfo(user.id, realName, nationality)) {
        // Update the user object with new values
        user.realName = realName;
        user.nationality = nationality;
        std::cout << "User information updated successfully!" << std::endl;
    }
    else {
        std::cout << "Failed to update user information." << std::endl;
    }
}

static void handleChangePassword(UserAuth& auth, User& user) {
    std::string currentPassword, newPassword, confirmPassword;

    std::cout << "\n========== Change Password ==========\n";
    std::cout << "Enter current password: ";
    std::cin >> currentPassword;

    std::cout << "Enter new password: ";
    std::cin >> newPassword;

    std::cout << "Confirm new password: ";
    std::cin >> confirmPassword;

    if (newPassword != confirmPassword) {
        std::cout << "New passwords do not match. Please try again." << std::endl;
        return;
    }

    if (auth.changePassword(user.email, currentPassword, newPassword)) {
        std::cout << "Password changed successfully!" << std::endl;
    }
    else {
        std::cout << "Failed to change password. Current password may be incorrect." << std::endl;
    }
}

// User menu - shown after successful login for regular users
static void showUserMenu(UserAuth& auth, WalletManager& walletManager, User& user) {
    int choice;

    while (true) {
        std::cout << "\n========== User Menu ==========\n";
        std::cout << "Welcome, " << user.email << "!" << std::endl;
        std::cout << "1. View Profile\n";
        std::cout << "2. Update Profile\n";
        std::cout << "3. Change Password\n";
        std::cout << "4. View Wallet Balance & History\n";
        std::cout << "5. Send Points to Another User\n";
        std::cout << "6. Logout\n";
        std::cout << "Enter your choice: ";
        std::cin >> choice;

        switch (choice) {
        case 1:
            handleViewProfile(user);
            break;
        case 2:
            handleUpdateProfile(auth, user);
            break;
        case 3:
            handleChangePassword(auth, user);
            handleLogout();
            return;
        case 4:
            handleViewOwnWalletBalanceAndHistory(walletManager, user);
            break;
        case 5:
            handleSendPointsToUser(walletManager, user);
            break;
        case 6:
            handleLogout();
            return;
        default:
            std::cout << "Invalid choice. Try again." << std::endl;
        }
    }
}

// Admin menu - shown after successful login for admin users
static void showAdminMenu(UserAuth& auth, WalletManager& walletManager, User& user) {
    int choice;

    while (true) {
        std::cout << "\n========== Admin Menu ==========\n";
        std::cout << "Welcome, Admin " << user.email << "!" << std::endl;
        std::cout << "1. View Profile\n";
        std::cout << "2. Update Profile\n";
        std::cout << "3. Create New User\n";
        std::cout << "4. Change Password\n";
        std::cout << "5. Top Up Master Wallet\n";
        std::cout << "6. Send Points from Master to User\n";
        std::cout << "7. View Master Wallet Balance & History\n";
        std::cout << "8. Logout\n";
        std::cout << "Enter your choice: ";
        std::cin >> choice;

        switch (choice) {
        case 1:
            handleViewProfile(user);
            break;
        case 2:
            handleUpdateProfile(auth, user);
            break;
        case 3:
            handleAdminCreateUser(auth);
            break;
        case 4:
            handleChangePassword(auth, user);
            handleLogout();
            return;
        case 5:
            handleTopUpMasterWallet(walletManager, user);
            break;
        case 6:
            handleSendPointsFromMaster(walletManager, user);
            break;
        case 7:
            handleViewMasterWalletBalanceAndHistory(walletManager, user);
            break;
        case 8:
            handleLogout();
            return;
        default:
            std::cout << "Invalid choice. Try again." << std::endl;
        }
    }
}

static void handleAdminCreateUser(UserAuth& auth) {
    std::string email, otp;

    std::cout << "Enter email for the new user: ";
    std::cin >> email;

    if (auth.createUserByAdmin(email)) {
        std::cout << "User creation initiated. An OTP has been sent to the user's email." << std::endl;
        std::cout << "Once the user shares the OTP with you, enter it to complete the process." << std::endl;
        std::cout << "Enter OTP: ";
        std::cin >> otp;

        User userInfo;
        if (auth.completeCreateUserByAdmin(email, otp, userInfo)) {
            std::cout << "User created successfully!" << std::endl;
        }
        else {
            std::cout << "OTP verification failed. User creation canceled." << std::endl;
        }
    }
    else {
        std::cout << "Failed to initiate user creation." << std::endl;
    }
}

static void handleTopUpMasterWallet(WalletManager& walletManager, const User& admin) {
    int points;
    
    std::cout << "\n========== Top Up Master Wallet ==========\n";
    std::cout << "Enter amount to add to master wallet: ";
    std::cin >> points;
    
    if (points <= 0) {
        std::cout << "Amount must be positive." << std::endl;
        return;
    }
    
    if (walletManager.topUpMasterWallet(admin.id, points)) {
        std::cout << "Successfully added " << points << " points to the master wallet." << std::endl;
        std::cout << "New balance: " << walletManager.getMasterWalletBalance() << " points" << std::endl;
    } else {
        std::cout << "Failed to top up master wallet. Please try again." << std::endl;
    }
}

static void handleSendPointsFromMaster(WalletManager& walletManager, const User& admin) {
    std::string toUserEmail;
    int points;
    
    std::cout << "\n========== Send Points from Master Wallet ==========\n";
    std::cout << "Current master wallet balance: " << walletManager.getMasterWalletBalance() << " points" << std::endl;
    std::cout << "Enter user email to send points to: ";
    std::cin >> toUserEmail;
    std::cout << "Enter amount to send: ";
    std::cin >> points;
    
    if (points <= 0) {
        std::cout << "Amount must be positive." << std::endl;
        return;
    }
    
    if (walletManager.sendPointsFromMasterToUserByEmail(admin.id, toUserEmail, points)) {
        std::cout << "Successfully sent " << points << " points to user: " << toUserEmail << std::endl;
        std::cout << "New master wallet balance: " << walletManager.getMasterWalletBalance() << " points" << std::endl;
    } else {
        std::cout << "Failed to send points. Check that you have enough balance and the user exists." << std::endl;
    }
}

static void handleSendPointsToUser(WalletManager& walletManager, const User& user) {
    std::string toUserEmail;
    int points;
    
    std::cout << "\n========== Send Points to User ==========\n";
    std::cout << "Your current balance: " << walletManager.getUserWalletBalance(user.id) << " points" << std::endl;
    std::cout << "Enter user email to send points to: ";
    std::cin >> toUserEmail;
    std::cout << "Enter amount to send: ";
    std::cin >> points;
    
    if (points <= 0) {
        std::cout << "Amount must be positive." << std::endl;
        return;
    }
    
    if (walletManager.sendPointsToUserByEmail(user.id, toUserEmail, points)) {
        std::cout << "Successfully sent " << points << " points to user: " << toUserEmail << std::endl;
        std::cout << "Your new balance: " << walletManager.getUserWalletBalance(user.id) << " points" << std::endl;
    } else {
        std::cout << "Failed to send points. Make sure you have enough balance and the recipient user exists." << std::endl;
    }
}

static void handleViewMasterWalletBalanceAndHistory(WalletManager& walletManager, const User& admin) {
    std::cout << "\n========== Master Wallet Information ==========\n";
    int balance = walletManager.getMasterWalletBalance();
    std::cout << "Current balance: " << balance << " points\n\n";
    
    std::cout << "Transaction History:\n";
    std::cout << "Timestamp | Type | Direction | Amount\n";
    std::cout << "---------------------------------------------\n";
    
    std::vector<TransactionRecord> history = walletManager.getMasterWalletHistory(admin.id);
    
    if (history.empty()) {
        std::cout << "No transaction history found." << std::endl;
    } else {
        for (const auto& record : history) {
            displayTransactionRecord(record);
        }
    }
}

static void handleViewOwnWalletBalanceAndHistory(WalletManager& walletManager, const User& user) {
    std::cout << "\n========== Your Wallet Information ==========\n";
    int balance = walletManager.getUserWalletBalance(user.id);
    std::cout << "Current balance: " << balance << " points\n\n";
    
    std::cout << "Transaction History:\n";
    std::cout << "Timestamp | Type | Direction | Amount\n";
    std::cout << "---------------------------------------------\n";
    
    std::vector<TransactionRecord> history = walletManager.getUserWalletHistory(user.id, user.id);
    
    if (history.empty()) {
        std::cout << "No transaction history found." << std::endl;
    } else {
        for (const auto& record : history) {
            displayTransactionRecord(record);
        }
    }
}

int main() {
    sqlite3* db = nullptr;
    const std::string dbPath = "main.db";
    
    if (sqlite3_open(dbPath.c_str(), &db) != SQLITE_OK) {
        std::cerr << "Failed to open database: " << sqlite3_errmsg(db) << std::endl;
        return 1;
    }
    
    UserAuth auth(db);
    WalletManager walletManager(db);
    
    int choice;
    
    try {
        while (true) {
            displayAuthMenu();
            std::cin >> choice;
            
            switch (choice) {
                case 1:
                    handleSignUp(auth);
                    break;
                case 2:
                    handleLogin(auth, walletManager);
                    break;
                case 3:
                    std::cout << "Exiting..." << std::endl;
                    sqlite3_close(db);
                    return 0;
                default:
                    std::cout << "Invalid choice. Try again." << std::endl;
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        sqlite3_close(db);
        return 1;
    }
}