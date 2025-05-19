#include "CredentialReader.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <iostream>

using json = nlohmann::json;

bool CredentialReader::readCredentials(const std::string& filePath, std::unordered_map<std::string, std::pair<std::string, std::string>>& credentials) {
    std::ifstream file(filePath);
    if (!file.is_open()) {
        std::cerr << "Failed to open credentials file: " << filePath << std::endl;
        return false;
    }

    try {
        json config = json::parse(file);

        // Process all entries in the JSON
        for (auto& [key, value] : config.items()) {
            // Check if this is an array (e.g., "admin" array)
            if (value.is_array()) {
                int count = 0;
                for (const auto& item : value) {
                    if (item.contains("username") && item.contains("password")) {
                        std::string username = item["username"].get<std::string>();
                        std::string password = item["password"].get<std::string>();

                        // Create a unique key for each entry in the array
                        std::string arrayKey = key + (count > 0 ? std::to_string(count) : "");
                        credentials[arrayKey] = { username, password };
                        count++;
                    }
                }
            }
            // Check if this is an object with "username" and "password"
            else if (value.is_object() && value.contains("username") && value.contains("password")) {
                std::string username = value["username"].get<std::string>();
                std::string password = value["password"].get<std::string>();
                credentials[key] = { username, password };
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error parsing credentials file: " << e.what() << std::endl;
        return false;
    }

    return !credentials.empty();
}
