# User Authentication and Wallet Management System

A C++ project that demonstrate a secure user authentication flow and transactional money transfer.

## Participants
- **Nguyễn Thanh Tùng** - [@k24dtcn384](tungnt.k24dtcn344@stu.ptit.edu.vn)
- **Lê Thanh Tiến** - [@k24dtcn384](tienlt.k24dtcn384@stu.ptit.edu.vn)
- **Trần Minh Đức** - [@k24dtcn365](ductm.k24dtcn365@stu.ptit.edu.vn)

## How to build

Prerequisites
- **Windows 10** or higher
- **Visual Studio 2019** or higher which includes:
  - **MSVC** compiler
  - **C++ CMake tools for Windows**
- **vcpkg** package manager

You should install these libraries first by vcpkg:
- **SQLite3** for database storage
- **OpenSSL** for cryptographic functions
- **Boost libraries** (system, date_time)
- **mailio** for email functionality
- **nlohmann_json** for configuration file parsing

Then follow the instructions below to integrate vcpkg with cmake and build the project.
https://learn.microsoft.com/en-us/vcpkg/get_started/get-started?pivots=shell-powershell


## Features

### Authentication
- Two-factor authentication using email OTP verification
- Password security with salt and hashing
- Profile management (view/update personal information)
- Admin user creation capability
- Forced password change for admin-created accounts

### Wallet System
- Master wallet controlled by administrators
- Individual user wallets with balance tracking
- Transaction types:
  - System top-up to master wallet
  - Distribution from master to user wallets
  - User-to-user transfers
- Transaction history

## How It Works

### Authentication Flow
1. User signs up with email and password or admin creates user account
2. One-time password (OTP) is sent to the user's email
3. User enters OTP to complete verification
4. User logs in with verified credentials and receives another OTP for login verification
5. After successful login, users can view/update their profile or manage their wallet

### Wallet Operations
1. **Admin Operations**:
   - Top up the master wallet with points
   - Distribute points from master wallet to specific users
   - View master wallet balance and complete transaction history

2. **User Operations**:
   - View personal wallet balance and transaction history
   - Send points to other users

### Security Measures
- All transactions are protected with SQL transaction blocks to ensure data integrity
- Role-based permissions enforce separation between admin and regular user actions
- Database operations include proper error handling and SQL injection protection