# NyxEnc: Military-Grade Encryption for Web3

[![MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Security: Strong](https://img.shields.io/badge/Security-Strong-green.svg)](docs/SECURITY.md)
[![Encryption: AES-256](https://img.shields.io/badge/Encryption-AES--256-purple.svg)](docs/WHITEPAPER.md)

End-to-End Encrypted, Wallet-Locked Content for Web3. This library provides military-grade encryption with blockchain-based access control and payment enforcement.

## 🔒 Security Features

- **AES-256 Encryption**: Industry-standard, FIPS 140-2 approved encryption
- **PBKDF2-SHA256**: Key derivation with 10,000-150,000 iterations
- **HMAC-SHA256**: Tamper-proof file integrity
- **Ed25519 Signatures**: Secure wallet verification
- **Client-Side Only**: All encryption/decryption happens in the browser
- **Zero Trust**: Server never sees plaintext or keys
- **Payment Enforcement**: Cryptographic payment verification for paid content

## 📦 Installation

```bash
npm install nyxenc
```

## 🚀 Quick Start

```typescript
import { 
  encryptContent, 
  generateNyxEncFile, 
  generateEncryptionKey 
} from 'nyxenc';

// Encrypt content
const content = "My secret message";
const key = generateEncryptionKey();
const encrypted = encryptContent(content, key);

// Create .nyxenc file
const metadata = {
  encryptionWallet: "7v91N7iuxY3xV5RbGP1YJwXNkV4YzXn2pKhZhWPu7Pv6", // Your Solana wallet
  planType: "free",
  createdAt: new Date().toISOString(),
  expiresAt: "2025-01-01T00:00:00.000Z",
  isPaid: false
};

const nyxEncFile = generateNyxEncFile(encrypted, metadata, key);
```

## 📖 Documentation

- [White Paper](docs/WHITEPAPER.md)
- [API Documentation](docs/API.md)
- [Security Model](docs/SECURITY.md)
- [Examples](examples/)

## 🛡️ Security Audit Status

This library implements best practices in cryptography and has been designed for maximum security:

- ✅ No server-side key storage
- ✅ No plaintext transmission
- ✅ Constant-time comparisons
- ✅ Strong key derivation
- ✅ Tamper detection
- ✅ Payment enforcement
- ✅ Expiration controls

## 🔍 File Format (.nyxenc)

The `.nyxenc` file format is a secure, versioned container that includes:

```typescript
interface NyxEncFile {
  version: string;
  metadata: {
    encryptionWallet: string;
    planType: string;
    createdAt: string;
    expiresAt: string;
    isPaid: boolean;
    // ... other metadata
  };
  encryptedContent: string;
  signature: string;
}
```

## 🧪 Testing

```bash
# Run tests
npm test

# Run tests with coverage
npm run coverage
```

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) first.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Security

If you discover a security vulnerability, please follow our [Security Policy](SECURITY.md).

## 🙏 Acknowledgments

- [crypto-js](https://github.com/brix/crypto-js) for AES implementation
- [Solana Web3.js](https://github.com/solana-labs/solana-web3.js) for blockchain integration
- [Noble Ed25519](https://github.com/paulmillr/noble-ed25519) for signatures

## 📬 Contact

- GitHub: [@nyxanonguard](https://github.com/nyxanonguard)
- Twitter: [@NyxAnonGuard](https://x.com/NyxAnonGuard)
- Email: contact@nyxanonguard.io

---

**Note**: This library is part of the Nyx Anon Guard project, focusing on secure content sharing in Web3. 