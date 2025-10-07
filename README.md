# 🔐 Self-Sovereign Identity Wallet

A decentralized identity management system built on the Stacks blockchain using Clarity smart contracts. Users can store, manage, and selectively share their verifiable credentials while maintaining full control over their digital identity.

## 🌟 Features

- **🆔 Profile Management**: Create and manage user profiles
- **📜 Credential Storage**: Store verifiable credentials (ID, education, employment, etc.)
- **🔑 Access Control**: Grant and revoke selective access to credentials
- **✅ Verification System**: Trusted issuers can verify credentials
- **🤝 Permission Requests**: Request and respond to credential verification requests
- **🏛️ Trusted Issuers**: Maintain a registry of trusted credential issuers

## 🚀 Getting Started

### Prerequisites

- [Clarinet](https://github.com/hirosystems/clarinet) installed
- Basic understanding of Clarity smart contracts

### Installation

1. Clone the repository
2. Navigate to the project directory
3. Deploy the contract using Clarinet

```bash
clarinet deploy
```

## 📖 Usage

### Creating a User Profile

```clarity
(contract-call? .Self-Sovereign-Identity-Wallet create-profile)
```

### Adding a Credential

```clarity
(contract-call? .Self-Sovereign-Identity-Wallet add-credential 
  "education-degree-001" 
  "education" 
  'SP1UNIVERSITY123 
  0x1234567890abcdef 
  (some u1000000))
```

### Granting Access to Credentials

```clarity
(contract-call? .Self-Sovereign-Identity-Wallet grant-access 
  'SP1REQUESTER123 
  "education-degree-001" 
  "read" 
  u144)
```

### Verifying Credentials (Issuer Only)

```clarity
(contract-call? .Self-Sovereign-Identity-Wallet verify-credential 
  'SP1CREDENTIALOWNER 
  "education-degree-001")
```

### Requesting Verification

```clarity
(contract-call? .Self-Sovereign-Identity-Wallet request-verification 
  'SP1CREDENTIALOWNER 
  "education-degree-001")
```

## 🔍 Read-Only Functions

- `get-user-profile`: Retrieve user profile information
- `get-credential`: Get specific credential details
- `get-access-permission`: Check access permissions
- `is-credential-accessible`: Verify if credential is accessible
- `is-credential-expired`: Check if credential has expired

## 🛡️ Security Features

- **Owner-only functions**: Critical functions restricted to contract owner
- **Access control**: Granular permission system for credential sharing
- **Expiration handling**: Time-based access and credential expiration
- **Trusted issuer registry**: Maintain verified credential issuers

## 📊 Data Structures

- **User Profiles**: Basic user information and statistics
- **Credentials**: Verifiable credentials with metadata
- **Access Permissions**: Time-bound access control records
- **Verification Requests**: Credential verification workflow
- **Trusted Issuers**: Registry of authorized credential issuers

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is open source and available under the MIT License.

## 🔗 Links

- [Stacks Documentation](https://docs.stacks.co/)
- [Clarity Language Reference](https://docs.stacks.co/clarity/)
- [Clarinet Documentation](https://github.com/hirosystems/clarinet)
```

**Git Commit Message:**
```
feat: implement self-sovereign identity wallet with credential management and selective sharing
```

**GitHub Pull Request Title:**
```
🔐 Add Self-Sovereign Identity Wallet Smart Contract
```

**GitHub Pull Request Description:**
```
## 🆕 What's Added

This PR introduces a comprehensive Self-Sovereign Identity Wallet smart contract that enables users to:

### ✨ Key Features
- **Profile Management**: Users can create and manage their identity profiles
- **Credential Storage**: Store verifiable credentials (education, employment, ID documents)
- **Selective Sharing**: Grant time-bound access to specific credentials
- **Verification System**: Trusted issuers can verify stored credentials
- **Access Control**: Granular permission management with expiration handling
- **Request Workflow**: Complete verification request and response system

### 🏗️ Technical Implementation
- **150+ lines** of production-ready Clarity code
- **5 data maps** for comprehensive data management
- **Error handling** with descriptive error codes
- **Time-based permissions** using block height
- **Read-only functions** for data querying
- **Security controls** with owner-only functions

### 📋 Contract Functions
- User profile creation and management
- Credential addition and verification
- Access permission granting/revoking
- Verification request handling
- Trusted issuer registry management

This implementation provides a solid foundation for decentralized identity management on the Stacks blockchain, giving users full control over their digital credentials while enabling secure, selective sharing.
