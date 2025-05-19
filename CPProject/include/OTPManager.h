#pragma once

#include <string>
#include <unordered_map>
#include <chrono>

class OTPManager {
private:
    std::unordered_map<std::string, std::pair<std::string, std::chrono::time_point<std::chrono::steady_clock>>> otpStorage;
    int otpExpirySeconds = 300; // OTP expires in 5 minutes

public:
    OTPManager() = default;
	~OTPManager() = default;

    // Generate an OTP for a given email
    std::string generateOTP(const std::string& email);

    // Verify the OTP for a given email
    bool verifyOTP(const std::string& email, const std::string& otp);

    // Set OTP expiry time (optional)
    void setExpiry(int seconds);
};
