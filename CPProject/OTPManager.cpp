#include "OTPManager.h"
#include <random>
#include <sstream>
#include <iomanip>
#include <chrono>

std::string OTPManager::generateOTP(const std::string& email) {
    // Generate a 6-digit random OTP
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(100000, 999999);
    std::string otp = std::to_string(dist(gen));

    // Store the OTP with the current timestamp
    auto now = std::chrono::steady_clock::now();
    otpStorage[email] = { otp, now };

    return otp;
}

bool OTPManager::verifyOTP(const std::string& email, const std::string& otp) {
    auto it = otpStorage.find(email);
    if (it == otpStorage.end()) {
        return false; // No OTP found for this email
    }

    auto [storedOTP, timestamp] = it->second;
    auto now = std::chrono::steady_clock::now();

    // Check if the OTP is valid and not expired
    if (storedOTP == otp && std::chrono::duration_cast<std::chrono::seconds>(now - timestamp).count() <= otpExpirySeconds) {
        otpStorage.erase(it); // Remove OTP after successful verification
        return true;
    }

    return false;
}

void OTPManager::setExpiry(int seconds) {
    otpExpirySeconds = seconds;
}
