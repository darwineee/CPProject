#pragma once

#include <string>
#include <unordered_map>

class CredentialReader {
public:
    static bool readCredentials(const std::string& filePath, std::unordered_map<std::string, std::pair<std::string, std::string>>& credentials);
};