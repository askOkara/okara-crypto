# Okara Crypto

Pure TypeScript/JavaScript end-to-end encryption library using X25519 key exchange.

## Features

- **X25519 Key Exchange** - Modern elliptic curve Diffie-Hellman
- **Argon2id Password Hashing** - Memory-hard KDF resistant to GPU attacks
- **AES-256-GCM Encryption** - Authenticated encryption with associated data
- **Recovery Codes** - PBKDF2-based account recovery system
- **Browser Native** - Works in all modern browsers using Web Crypto API
- **Zero Dependencies*** - Only uses @noble/curves and @phi-ag/argon2

## Installation

```bash
npm install @noble/curves @phi-ag/argon2
```

## Usage

### Generate Key Pair

```typescript
import { generateX25519KeyPair } from './client-e2ee';

const { publicKey, privateKey } = await generateX25519KeyPair();
// publicKey: base64-encoded public key
// privateKey: PEM-formatted private key
```

### Password-Based Key Encryption

```typescript
import {
  generateSalt,
  hashPasscode,
  encryptPrivateKey,
  decryptPrivateKey
} from './client-e2ee';

// Generate salt for key derivation
const salt = generateSalt();

// Hash passcode (with optional pepper for added security)
const pepper = 'your-secret-pepper'; // Optional
const passcodeHash = await hashPasscode('123456', salt, pepper);

// Encrypt private key with passcode
const encryptedKey = await encryptPrivateKey(privateKey, '123456', salt, pepper);

// Decrypt private key with passcode
const decryptedKey = await decryptPrivateKey(encryptedKey, '123456', salt, pepper);
```

### Message Encryption/Decryption

```typescript
import { encryptMessage, decryptMessage } from './client-e2ee';

// Alice encrypts message for Bob using Bob's public key
const encrypted = await encryptMessage('Hello Bob!', bobPublicKey);

// Bob decrypts message using his private key
const decrypted = await decryptMessage(encrypted, bobPrivateKey);
```

### Recovery Codes

```typescript
import { generateRecoveryCodes, decryptPasscodeWithRecoveryCode } from './client-e2ee';

// Generate 6 recovery codes
const { recoveryCodes, recoveryCodesData } = await generateRecoveryCodes('123456', salt);

// Show recovery codes to user (one-time display)
console.log('Save these recovery codes:', recoveryCodes);

// Store recoveryCodesData in database (hashed + encrypted)
saveToDatabase(recoveryCodesData);

// Later: recover passcode using recovery code
const recoveredPasscode = await decryptPasscodeWithRecoveryCode(
  recoveryCodesData[0].encryptedPasscode,
  recoveryCodes[0],
  salt
);
```

## Security

- **X25519**: Curve25519 ECDH key agreement
- **Argon2id**: Memory-hard KDF (128 MB, 4 iterations, 2 threads)
- **AES-256-GCM**: Authenticated encryption
- **HKDF-SHA512**: Key derivation for shared secrets
- **PBKDF2-SHA256**: Recovery code key derivation (100k iterations)

## Browser Compatibility

Requires Web Crypto API support:
- Chrome/Edge 60+
- Firefox 57+
- Safari 11+
- Opera 47+

## Architecture

### Message Encryption Flow

```
Sender                          Recipient
  |                                |
  | 1. Generate ephemeral key pair |
  |    (X25519)                    |
  |                                |
  | 2. ECDH with recipient's       |
  |    public key                  |
  |                                |
  | 3. HKDF-SHA512 to derive       |
  |    AES key                     |
  |                                |
  | 4. AES-256-GCM encrypt         |
  |                                |
  | 5. Send: ephemeral_pub ||      |
  |    IV || tag || ciphertext     |
  |---------------------------------
                                   |
                  6. ECDH with ephemeral_pub
                     and own private key
                                   |
                  7. HKDF-SHA512 to derive
                     same AES key
                                   |
                  8. AES-256-GCM decrypt
```

### Passcode Flow

```
1. User enters 6-digit passcode
2. Optional: HMAC-SHA256 with pepper (server secret)
3. Argon2id derives 32-byte key
4. AES-256-GCM encrypts private key with derived key
5. Store: salt + encrypted_private_key
```

## License

MIT

## Credits

Built by [okara.ai](https://okara.ai) for secure LLM Chat applications.