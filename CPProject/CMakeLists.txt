# CMakeList.txt : CMake project for CPProject, include source and define
# project specific logic here.
#

# Add source to this project's executable.
add_executable(CPProject 
    "CPProject.cpp" 
    "UserAuth.cpp"
    "CredentialReader.cpp"
    "OTPManager.cpp"
    "EmailSender.cpp"
    "WalletManager.cpp"
    
    "include/UserAuth.h" 
    "include/CredentialReader.h"
    "include/OTPManager.h"
    "include/EmailSender.h" 
    "include/WalletManager.h")

# Add include directories
target_include_directories(CPProject PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Set C++ standard for the target
target_compile_features(CPProject PRIVATE cxx_std_20)

set(CREDENTIALS_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/credentials.json")
set(CREDENTIALS_DEST "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>/credentials.json")

add_custom_command(
    TARGET CPProject POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CREDENTIALS_SOURCE}
        ${CREDENTIALS_DEST}
    COMMENT "Copying credentials.json to executable directory ($<CONFIG>)"
)

set(CMAKE_PREFIX_PATH "C:/Program Files/vcpkg/installed/x64-windows" CACHE STRING "Path to vcpkg installed libraries")

find_package(Boost REQUIRED COMPONENTS system date_time)
find_package(OpenSSL REQUIRED)
find_package(mailio CONFIG REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

target_link_libraries(CPProject PRIVATE
    mailio
    Boost::system
    OpenSSL::SSL
    OpenSSL::Crypto
    SQLite::SQLite3
    nlohmann_json::nlohmann_json)