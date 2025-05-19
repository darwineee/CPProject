#pragma once

#include <string>

class EmailSender {
private:
    std::string smtpServer;
    int smtpPort;
    std::string senderEmail;
    std::string senderPassword;

public:
    EmailSender(
        const std::string& email = "",
        const std::string& password = "",
        const std::string& server = "smtp.gmail.com",
        const int port = 465
    );
	~EmailSender() = default;

    // Send an email
    bool sendEmail(
        const std::string& to,
        const std::string& subject,
        const std::string& body
    );
};
