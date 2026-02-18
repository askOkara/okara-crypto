/**
 * Okara Crypto - X25519 E2EE Core
 *
 * Pure cryptographic functions for end-to-end encryption using X25519.
 * No storage, no sessions, just crypto primitives.
 *
 * Features:
 * - X25519 key pair generation using @noble/curves
 * - Argon2id passcode hashing (memory-hard KDF)
 * - AES-GCM encryption/decryption
 * - Recovery codes with PBKDF2
 * - Message encryption/decryption with ECDH
 */

import initialize from '@phi-ag/argon2/fetch';
import { Argon2Type } from '@phi-ag/argon2';
import { x25519 } from '@noble/curves/ed25519.js';

// Argon2id parameters for enhanced security
const ARGON2_PARAMS = {
    memoryCost: 128 * 1024, // 128 MB memory usage
    timeCost: 4,           // 4 iterations
    parallelism: 2,        // 2 parallel threads
    hashLength: 32         // 32 bytes output
};

// Initialize argon2 instance
let argon2Instance: any = null;

async function getArgon2Instance() {
    if (!argon2Instance) {
        // For browser environment, we need to load the WASM file from public directory
        const wasmUrl = '/argon2.wasm';
        argon2Instance = await initialize(wasmUrl);
    }
    return argon2Instance;
}

/**
 * Convert Uint8Array to base64 string
 */
function uint8ArrayToBase64(bytes: Uint8Array): string {
    return btoa(String.fromCharCode(...bytes));
}

/**
 * Convert base64 string to Uint8Array
 */
function base64ToUint8Array(base64: string): Uint8Array {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

/**
 * Convert private key Uint8Array to PEM format
 */
function privateKeyToPem(privateKeyBytes: Uint8Array): string {
    const base64Key = uint8ArrayToBase64(privateKeyBytes);
    return `-----BEGIN PRIVATE KEY-----\n${base64Key.match(/.{1,64}/g)?.join('\n') || base64Key}\n-----END PRIVATE KEY-----`;
}

/**
 * Extract raw 32-byte X25519 private key from PKCS#8 format
 */
function extractRawKeyFromPKCS8(pkcs8Bytes: Uint8Array): Uint8Array {
    // Look for OCTET STRING tag (0x04) followed by length 0x20 (32 bytes)
    for (let i = 0; i <= pkcs8Bytes.length - 34; i++) {
        if (pkcs8Bytes[i] === 0x04 && pkcs8Bytes[i + 1] === 0x20) {
            const rawKey = pkcs8Bytes.slice(i + 2, i + 34);
            if (rawKey.length === 32) {
                return rawKey;
            }
        }
    }

    // Fallback: try the last 32 bytes
    if (pkcs8Bytes.length >= 32) {
        return pkcs8Bytes.slice(-32);
    }

    throw new Error('Could not extract raw key from PKCS#8 format');
}

/**
 * Convert PEM private key to Uint8Array
 */
function pemToPrivateKeyBytes(pem: string): Uint8Array {
    const pemHeader = '-----BEGIN PRIVATE KEY-----';
    const pemFooter = '-----END PRIVATE KEY-----';
    const pemContents = pem
        .replace(pemHeader, '')
        .replace(pemFooter, '')
        .replace(/\s/g, '');

    const decodedBytes = base64ToUint8Array(pemContents);

    // Check if this is PKCS#8 format (48+ bytes) or raw format (32 bytes)
    if (decodedBytes.length === 48 || decodedBytes.length > 32) {
        return extractRawKeyFromPKCS8(decodedBytes);
    } else if (decodedBytes.length === 32) {
        return decodedBytes;
    } else {
        throw new Error(`Invalid private key format: expected 32 or 48+ bytes, got ${decodedBytes.length} bytes`);
    }
}

/**
 * Generate X25519 key pair using @noble/curves
 */
export async function generateX25519KeyPair(): Promise<{
    publicKey: string;
    privateKey: string;
}> {
    try {
        // Generate random private key (32 bytes)
        const privateKeyBytes = crypto.getRandomValues(new Uint8Array(32));

        // Get public key from private key
        const publicKeyBytes = x25519.getPublicKey(privateKeyBytes);

        // Convert to base64 for storage
        const publicKeyBase64 = uint8ArrayToBase64(publicKeyBytes);
        const privateKeyPem = privateKeyToPem(privateKeyBytes);

        return {
            publicKey: publicKeyBase64,
            privateKey: privateKeyPem
        };
    } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error';
        throw new Error(`Failed to generate X25519 key pair: ${errorMessage}`);
    }
}

/**
 * Generate random salt for password hashing
 */
export function generateSalt(): string {
    const salt = new Uint8Array(32);
    crypto.getRandomValues(salt);
    return Array.from(salt, byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Hash passcode using Argon2id with HMAC pepper
 */
export async function hashPasscode(passcode: string, salt: string, pepper?: string): Promise<string> {
    try {
        const saltBuffer = new Uint8Array(salt.match(/.{2}/g)!.map(byte => parseInt(byte, 16)));

        let inputData = passcode;

        // Apply HMAC pepper if provided
        if (pepper) {
            const pepperedPasscode = await crypto.subtle.sign(
                'HMAC',
                await crypto.subtle.importKey(
                    'raw',
                    new TextEncoder().encode(pepper),
                    { name: 'HMAC', hash: 'SHA-256' },
                    false,
                    ['sign']
                ),
                new TextEncoder().encode(passcode)
            );

            inputData = Array.from(new Uint8Array(pepperedPasscode),
                byte => byte.toString(16).padStart(2, '0')).join('');
        }

        const argon2 = await getArgon2Instance();
        const hashResult = argon2.hash(inputData, {
            salt: saltBuffer,
            type: Argon2Type.Argon2id,
            memoryCost: ARGON2_PARAMS.memoryCost,
            timeCost: ARGON2_PARAMS.timeCost,
            parallelism: ARGON2_PARAMS.parallelism,
            hashLength: ARGON2_PARAMS.hashLength
        });

        return Array.from(new Uint8Array(hashResult.hash), byte => byte.toString(16).padStart(2, '0')).join('');
    } catch (error) {
        throw new Error(`Failed to hash passcode: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
}

/**
 * Encrypt private key with passcode using Argon2id + AES-GCM
 */
export async function encryptPrivateKey(privateKey: string, passcode: string, salt: string, pepper?: string): Promise<string> {
    try {
        const saltBuffer = new Uint8Array(salt.match(/.{2}/g)!.map(byte => parseInt(byte, 16)));

        let inputData = passcode;

        // Apply HMAC pepper if provided
        if (pepper) {
            const pepperedPasscode = await crypto.subtle.sign(
                'HMAC',
                await crypto.subtle.importKey(
                    'raw',
                    new TextEncoder().encode(pepper),
                    { name: 'HMAC', hash: 'SHA-256' },
                    false,
                    ['sign']
                ),
                new TextEncoder().encode(passcode)
            );

            inputData = Array.from(new Uint8Array(pepperedPasscode),
                byte => byte.toString(16).padStart(2, '0')).join('');
        }

        const argon2 = await getArgon2Instance();
        const hashResult = argon2.hash(inputData, {
            salt: saltBuffer,
            type: Argon2Type.Argon2id,
            memoryCost: ARGON2_PARAMS.memoryCost,
            timeCost: ARGON2_PARAMS.timeCost,
            parallelism: ARGON2_PARAMS.parallelism,
            hashLength: ARGON2_PARAMS.hashLength
        });

        // Generate random IV
        const iv = crypto.getRandomValues(new Uint8Array(16));

        // Import derived key for encryption
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            new Uint8Array(hashResult.hash),
            { name: 'AES-GCM' },
            false,
            ['encrypt']
        );

        // Encrypt private key
        const encrypted = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                additionalData: new TextEncoder().encode('okara-e2ee-private-key')
            },
            cryptoKey,
            new TextEncoder().encode(privateKey)
        );

        // Combine IV + encrypted data
        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv);
        combined.set(new Uint8Array(encrypted), iv.length);

        return btoa(String.fromCharCode(...combined));
    } catch (error) {
        throw new Error(`Failed to encrypt private key: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
}

/**
 * Decrypt private key with passcode using Argon2id + AES-GCM
 */
export async function decryptPrivateKey(encryptedPrivateKey: string, passcode: string, salt: string, pepper?: string): Promise<string> {
    const saltBuffer = new Uint8Array(salt.match(/.{2}/g)!.map(byte => parseInt(byte, 16)));

    let inputData = passcode;

    // Apply HMAC pepper if provided
    if (pepper) {
        const pepperedPasscode = await crypto.subtle.sign(
            'HMAC',
            await crypto.subtle.importKey(
                'raw',
                new TextEncoder().encode(pepper),
                { name: 'HMAC', hash: 'SHA-256' },
                false,
                ['sign']
            ),
            new TextEncoder().encode(passcode)
        );

        inputData = Array.from(new Uint8Array(pepperedPasscode),
            byte => byte.toString(16).padStart(2, '0')).join('');
    }

    // Derive key using Argon2id
    const argon2 = await getArgon2Instance();
    const hashResult = argon2.hash(inputData, {
        salt: saltBuffer,
        type: Argon2Type.Argon2id,
        memoryCost: ARGON2_PARAMS.memoryCost,
        timeCost: ARGON2_PARAMS.timeCost,
        parallelism: ARGON2_PARAMS.parallelism,
        hashLength: ARGON2_PARAMS.hashLength
    });

    // Decode combined data
    const combined = new Uint8Array(atob(encryptedPrivateKey).split('').map(c => c.charCodeAt(0)));

    // Extract IV and encrypted data
    const iv = combined.slice(0, 16);
    const encrypted = combined.slice(16);

    // Import derived key for decryption
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        new Uint8Array(hashResult.hash),
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    );

    // Decrypt private key
    const decrypted = await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv: iv,
            additionalData: new TextEncoder().encode('okara-e2ee-private-key')
        },
        cryptoKey,
        encrypted
    );

    return new TextDecoder().decode(decrypted);
}

/**
 * Recovery Code Interface
 */
export interface RecoveryCodeData {
    hash: string;
    encryptedPasscode: string;
    used: boolean;
}

/**
 * Generate a single random recovery code (6 digits)
 */
function generateRecoveryCode(): string {
    const randomValues = new Uint8Array(3);
    crypto.getRandomValues(randomValues);

    const min = 100000;
    const max = 999999;
    const range = max - min + 1;

    const randomValue = (randomValues[0] << 16) | (randomValues[1] << 8) | randomValues[2];
    const code = (randomValue % range) + min;

    return code.toString();
}

/**
 * Hash a recovery code using SHA-256
 */
async function hashRecoveryCode(recoveryCode: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(recoveryCode);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hashBuffer), byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Encrypt passcode with recovery code using PBKDF2 + AES-GCM
 */
async function encryptPasscodeWithRecoveryCode(passcode: string, recoveryCode: string, salt: string): Promise<string> {
    try {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(recoveryCode),
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );

        const saltBuffer = new Uint8Array(salt.match(/.{2}/g)!.map(byte => parseInt(byte, 16)));

        const key = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: saltBuffer,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt']
        );

        const iv = crypto.getRandomValues(new Uint8Array(12));

        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv },
            key,
            encoder.encode(passcode)
        );

        const combined = new Uint8Array(iv.length + encrypted.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(encrypted), iv.length);

        return Array.from(combined, byte => byte.toString(16).padStart(2, '0')).join('');
    } catch (error) {
        throw new Error(`Failed to encrypt passcode with recovery code: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
}

/**
 * Decrypt passcode with recovery code using PBKDF2 + AES-GCM
 */
export async function decryptPasscodeWithRecoveryCode(encryptedPasscode: string, recoveryCode: string, salt: string): Promise<string> {
    try {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(recoveryCode),
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );

        const saltBuffer = new Uint8Array(salt.match(/.{2}/g)!.map(byte => parseInt(byte, 16)));

        const key = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: saltBuffer,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
        );

        const encryptedBuffer = new Uint8Array(encryptedPasscode.match(/.{2}/g)!.map(byte => parseInt(byte, 16)));
        const iv = encryptedBuffer.slice(0, 12);
        const ciphertext = encryptedBuffer.slice(12);

        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv },
            key,
            ciphertext
        );

        return new TextDecoder().decode(decrypted);
    } catch (error) {
        throw new Error('Invalid recovery code or corrupted data');
    }
}

/**
 * Generate 6 recovery codes
 */
export async function generateRecoveryCodes(passcode: string, salt: string): Promise<{
    recoveryCodes: string[];
    recoveryCodesData: RecoveryCodeData[];
}> {
    const recoveryCodes: string[] = [];
    const recoveryCodesData: RecoveryCodeData[] = [];

    for (let i = 0; i < 6; i++) {
        const code = generateRecoveryCode();
        recoveryCodes.push(code);

        const hash = await hashRecoveryCode(code);
        const encryptedPasscode = await encryptPasscodeWithRecoveryCode(passcode, code, salt);

        recoveryCodesData.push({
            hash,
            encryptedPasscode,
            used: false
        });
    }

    return { recoveryCodes, recoveryCodesData };
}

/**
 * Derive HKDF key using Web Crypto API
 */
async function deriveHKDFKey(sharedSecret: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array> {
    const sharedSecretBuffer = new Uint8Array(sharedSecret);
    const saltBuffer = new Uint8Array(salt);
    const infoBuffer = new Uint8Array(info);

    const sharedSecretKey = await crypto.subtle.importKey(
        'raw',
        sharedSecretBuffer,
        { name: 'HKDF' },
        false,
        ['deriveBits']
    );

    const encryptionKey = await crypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-512',
            salt: saltBuffer,
            info: infoBuffer,
        },
        sharedSecretKey,
        length * 8
    );

    // Create a proper Uint8Array with a fresh ArrayBuffer to satisfy TypeScript
    const sourceArray = new Uint8Array(encryptionKey as ArrayBuffer);
    const resultBuffer = new ArrayBuffer(length);
    const resultArray = new Uint8Array(resultBuffer);
    resultArray.set(sourceArray);
    return resultArray;
}

/**
 * Encrypt message using X25519 ECDH + AES-GCM
 */
export async function encryptMessage(message: string, publicKeyBase64: string): Promise<string> {
    try {
        // Generate ephemeral X25519 key pair
        const ephemeralPrivateKey = crypto.getRandomValues(new Uint8Array(32));
        const ephemeralPublicKey = x25519.getPublicKey(ephemeralPrivateKey);

        // Convert base64 public key to Uint8Array
        const recipientPublicKey = base64ToUint8Array(publicKeyBase64);

        // Perform X25519 key agreement
        const sharedSecret = x25519.getSharedSecret(ephemeralPrivateKey, recipientPublicKey);

        // Derive encryption key using HKDF
        const encryptionKey = await deriveHKDFKey(
            sharedSecret,
            new TextEncoder().encode('okara-e2ee-salt'),
            new TextEncoder().encode('okara-e2ee-key'),
            32
        );

        // Generate random IV
        const iv = crypto.getRandomValues(new Uint8Array(16));

        // Import encryption key
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            new Uint8Array(encryptionKey),
            { name: 'AES-GCM' },
            false,
            ['encrypt']
        );

        // Encrypt message
        const encrypted = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                additionalData: new TextEncoder().encode('okara-e2ee-message')
            },
            cryptoKey,
            new TextEncoder().encode(message)
        );

        // Extract auth tag (last 16 bytes of encrypted data)
        const encryptedArray = new Uint8Array(encrypted);
        const ciphertext = encryptedArray.slice(0, -16);
        const authTag = encryptedArray.slice(-16);

        // Combine: ephemeral public key + IV + authTag + ciphertext
        const combined = new Uint8Array(32 + 16 + 16 + ciphertext.length);
        combined.set(ephemeralPublicKey, 0);
        combined.set(iv, 32);
        combined.set(authTag, 48);
        combined.set(ciphertext, 64);

        return uint8ArrayToBase64(combined);
    } catch (error) {
        throw new Error('Failed to encrypt message');
    }
}

/**
 * Decrypt message using X25519 ECDH + AES-GCM
 */
export async function decryptMessage(encryptedData: string, privateKeyPem: string): Promise<string> {
    try {
        // Convert PEM private key to bytes
        const privateKeyBytes = pemToPrivateKeyBytes(privateKeyPem);

        // Decode base64 encrypted data
        const encryptedBuffer = base64ToUint8Array(encryptedData);

        // Extract components
        const ephemeralPublicKey = encryptedBuffer.slice(0, 32);
        const iv = encryptedBuffer.slice(32, 48);
        const authTag = encryptedBuffer.slice(48, 64);
        const ciphertext = encryptedBuffer.slice(64);

        // Perform X25519 key agreement
        const sharedSecret = x25519.getSharedSecret(privateKeyBytes, ephemeralPublicKey);

        // Derive encryption key using HKDF
        const encryptionKey = await deriveHKDFKey(
            sharedSecret,
            new TextEncoder().encode('okara-e2ee-salt'),
            new TextEncoder().encode('okara-e2ee-key'),
            32
        );

        // Import encryption key
        const cryptoKey = await crypto.subtle.importKey(
            'raw',
            new Uint8Array(encryptionKey),
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );

        // Combine ciphertext + auth tag for AES-GCM
        const encryptedMessageWithTag = new Uint8Array(ciphertext.length + authTag.length);
        encryptedMessageWithTag.set(ciphertext);
        encryptedMessageWithTag.set(authTag, ciphertext.length);

        // Decrypt message
        const decrypted = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                additionalData: new TextEncoder().encode('okara-e2ee-message')
            },
            cryptoKey,
            encryptedMessageWithTag
        );

        return new TextDecoder().decode(decrypted);
    } catch (error) {
        throw new Error('Failed to decrypt message');
    }
}
