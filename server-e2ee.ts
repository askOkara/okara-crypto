/**
 * Server-Side E2EE Utilities (v2)
 *
 * X25519-based end-to-end encryption for secure messaging
 *
 * This file contains server-side E2EE functions for:
 * - Message encryption with X25519 public keys
 * - Database operations
 * - Validation helpers
 *
 * Note: Key generation and passcode hashing are done client-side
 */

import 'server-only';

/**
 * Encrypt message with X25519 public key using ECDH key agreement
 * Used server-side to encrypt messages before storing in database
 *
 * This function uses a hybrid approach:
 * 1. Generate an ephemeral X25519 key pair
 * 2. Perform ECDH key agreement with user's public key
 * 3. Derive encryption key using HKDF-SHA512
 * 4. Encrypt the message with AES-GCM using the derived key
 * 5. Combine ephemeral public key + IV + auth tag + encrypted message
 */
export async function encryptMessageWithX25519PublicKey(message: string, publicKeyBase64: string): Promise<string> {
    const { randomBytes, createCipheriv } = require('crypto');
    const { webcrypto } = require('crypto');

    try {
        // Generate ephemeral X25519 key pair using Web Crypto API
        const ephemeralKeyPair = await webcrypto.subtle.generateKey(
            {
                name: 'X25519',
            },
            true, // extractable
            ['deriveKey', 'deriveBits']
        );

        // Convert base64 public key to ArrayBuffer and import it
        const userPublicKeyBuffer = Buffer.from(publicKeyBase64, 'base64');
        const userPublicKey = await webcrypto.subtle.importKey(
            'raw',
            userPublicKeyBuffer,
            {
                name: 'X25519',
            },
            true, // extractable
            [] // key usages
        );

        // Perform X25519 key agreement using Web Crypto API
        const sharedSecret = await webcrypto.subtle.deriveBits(
            {
                name: 'X25519',
                public: userPublicKey,
            },
            ephemeralKeyPair.privateKey,
            256 // length of the derived key in bits
        );

        // Derive encryption key using HKDF-SHA512
        const encryptionKey = require('crypto').hkdfSync(
            'sha512',
            Buffer.from(sharedSecret),
            Buffer.from('bti-e2ee-salt', 'utf8'),
            Buffer.from('bti-e2ee-key', 'utf8'),
            32 // 32 bytes for AES-256
        );

        // Generate random IV for AES-GCM (128 bits)
        const iv = randomBytes(16);

        // Encrypt message with AES-GCM using the derived key
        const cipher = createCipheriv('aes-256-gcm', encryptionKey, iv);
        cipher.setAAD(Buffer.from('bti-e2ee-message', 'utf8')); // Additional authenticated data

        let encryptedMessage = cipher.update(message, 'utf8', 'hex');
        encryptedMessage += cipher.final('hex');
        const authTag = cipher.getAuthTag();

        // Export ephemeral public key as raw buffer
        const ephemeralPublicKeyBuffer = await webcrypto.subtle.exportKey('raw', ephemeralKeyPair.publicKey);

        // Combine all parts: ephemeral public key + IV + authTag + AES-encrypted message
        const combined = Buffer.concat([
            Buffer.from(ephemeralPublicKeyBuffer),    // Ephemeral public key (32 bytes)
            iv,                                       // AES IV (16 bytes)
            authTag,                                  // AES authentication tag (16 bytes)
            Buffer.from(encryptedMessage, 'hex')      // AES-encrypted message
        ]);

        return combined.toString('base64');
    } catch (error) {
        throw new Error('Failed to encrypt message');
    }
}
