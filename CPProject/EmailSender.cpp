#include "EmailSender.h"
#include "CredentialReader.h"
#include <mailio/message.hpp>
#include <mailio/smtp.hpp>
#include <iostream>

EmailSender::EmailSender(
    const std::string& email,
    const std::string& password,
    const std::string& server,
    const int port
) : smtpServer(server), smtpPort(port), senderEmail(email), senderPassword(password) {}

bool EmailSender::sendEmail(const std::string& to, const std::string& subject, const std::string& body) {
    try {
        std::cout << "Sending email..." << std::endl;

        mailio::message msg;
        msg.from(mailio::mail_address("OTP service", senderEmail));
        msg.add_recipient(mailio::mail_address("Customer", to));
        msg.subject(subject);
        msg.content(body);

        mailio::smtps conn(smtpServer, smtpPort);
        conn.authenticate(senderEmail, senderPassword, mailio::smtps::auth_method_t::LOGIN);
        conn.submit(msg);

        std::cout << "Email sent successfully!" << std::endl;
		return true;
    }
    catch (const std::exception& e) {
        std::cerr << "Error when sent email: " << e.what() << std::endl;
        return false;
    }
}
