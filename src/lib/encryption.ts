/**
 * Core encryption functionality for NyxEnc
 * @module encryption
 */

import CryptoJS from 'crypto-js';
import { PublicKey, Connection, Transaction } from '@solana/web3.js';
import { verify } from '@noble/ed25519';
import bs58 from 'bs58';
import { createMemoInstruction } from '@solana/spl-memo';
import type { 
  NyxEncFile, 
  NyxEncFileMetadata, 
  ValidationResult
} from './types';

// Current version of the .nyxenc format
export const NYXENC_VERSION = '1.0.0';

/**
 * Generate a cryptographically secure random encryption key
 * @returns {string} 256-bit encryption key as a hex string
 */
export function generateEncryptionKey(): string {
  return CryptoJS.lib.WordArray.random(32).toString();
}

/**
 * Encrypt content using AES-256
 * @param {string} content - Content to encrypt
 * @param {string} key - Encryption key
 * @returns {string} Encrypted content
 * @throws {Error} If encryption fails
 */
export function encryptContent(content: string, key: string): string {
  try {
    const stringContent = typeof content === 'object' ? JSON.stringify(content) : content;
    return CryptoJS.AES.encrypt(stringContent, key).toString();
  } catch (err) {
    throw new Error('Failed to encrypt content');
  }
}

/**
 * Decrypt content using AES-256
 * @param {string} encryptedContent - Content to decrypt
 * @param {string} key - Decryption key
 * @returns {string} Decrypted content
 * @throws {Error} If decryption fails
 */
export function decryptContent(encryptedContent: string, key: string): string {
  try {
    // Handle JSON-encoded content
    let contentToDecrypt = encryptedContent;
    try {
      const parsed = JSON.parse(encryptedContent);
      contentToDecrypt = parsed.content || parsed;
    } catch {
      contentToDecrypt = encryptedContent;
    }

    // Decrypt using AES-256
    const bytes = CryptoJS.AES.decrypt(contentToDecrypt, key);
    const decrypted = bytes.toString(CryptoJS.enc.Utf8);
    
    if (!decrypted) {
      throw new Error('Decryption resulted in empty content');
    }
    
    // Handle JSON content
    try {
      const parsed = JSON.parse(decrypted);
      return typeof parsed === 'string' ? parsed : JSON.stringify(parsed, null, 2);
    } catch {
      return decrypted;
    }
  } catch (err) {
    throw new Error('Failed to decrypt content. The encryption key may be invalid.');
  }
}

/**
 * Generate a high-entropy nonce for enhanced security
 * @returns {string} 256-bit random nonce as hex string
 */
export function generateSecurityNonce(): string {
  return CryptoJS.lib.WordArray.random(32).toString();
}

/**
 * Generate a .nyxenc file with encrypted content and metadata
 * @param {string} encryptedContent - AES-256 encrypted content
 * @param {NyxEncFileMetadata} metadata - File metadata
 * @param {string} encryptionKey - Key used for encryption
 * @returns {NyxEncFile} Complete .nyxenc file structure
 * @throws {Error} If file generation fails
 */
export function generateNyxEncFile(
  encryptedContent: string,
  metadata: NyxEncFileMetadata,
  encryptionKey: string
): NyxEncFile {
  try {
    // Add security nonce if not present
    const enhancedMetadata = {
      ...metadata,
      securityNonce: metadata.securityNonce || generateSecurityNonce()
    };

    // Create file structure
    const fileContent: NyxEncFile = {
      version: NYXENC_VERSION,
      metadata: enhancedMetadata,
      encryptedContent,
      signature: ''
    };

    // Generate integrity signature using the provided encryption key
    const contentForSigning = JSON.stringify({
      version: fileContent.version,
      metadata: fileContent.metadata,
      encryptedContent: fileContent.encryptedContent
    });
    
    fileContent.signature = CryptoJS.HmacSHA256(contentForSigning, encryptionKey).toString();
    
    return fileContent;
  } catch (err) {
    throw new Error('Failed to generate .nyxenc file');
  }
}

/**
 * Validate a .nyxenc file structure and format
 * @param {string} fileContent - Raw file content
 * @returns {ValidationResult} Validation result
 */
export function validateNyxEncFile(fileContent: string): ValidationResult {
  try {
    let jsonContent = fileContent;
    
    // Handle PEM-style format
    if (fileContent.includes('-----BEGIN NYXENCRYPTED FILE-----')) {
      const startMarker = '-----BEGIN NYXENCRYPTED FILE-----';
      const endMarker = '-----END NYXENCRYPTED FILE-----';
      const startIndex = fileContent.indexOf(startMarker) + startMarker.length;
      const endIndex = fileContent.indexOf(endMarker);
      
      if (startIndex === -1 || endIndex === -1 || startIndex >= endIndex) {
        return {
          valid: false,
          error: 'Invalid .nyxenc file format - malformed header/footer'
        };
      }
      
      jsonContent = fileContent.substring(startIndex, endIndex).trim();
    }
    
    // Parse and validate JSON structure
    const parsed = JSON.parse(jsonContent);
    
    if (!parsed.version || !parsed.metadata || !parsed.encryptedContent || !parsed.signature) {
      return {
        valid: false,
        error: 'Invalid .nyxenc file format - missing required fields'
      };
    }

    // Validate version
    if (parsed.version !== NYXENC_VERSION) {
      return {
        valid: false,
        error: `Unsupported .nyxenc file version: ${parsed.version}`
      };
    }

    // Validate metadata
    const metadata = parsed.metadata;
    if (!metadata.encryptionWallet || !metadata.planType || !metadata.createdAt) {
      return {
        valid: false,
        error: 'Invalid metadata in .nyxenc file'
      };
    }

    // Validate wallet address
    if (!isValidPublicKey(metadata.encryptionWallet)) {
      return {
        valid: false,
        error: 'Invalid wallet address in .nyxenc file'
      };
    }

    return {
      valid: true,
      file: parsed as NyxEncFile
    };
  } catch (err) {
    return {
      valid: false,
      error: 'Invalid .nyxenc file format - not valid JSON'
    };
  }
}

/**
 * Verify the integrity of a .nyxenc file
 * @param {NyxEncFile} nyxEncFile - File to verify
 * @param {string} encryptionKey - Key to verify with
 * @returns {boolean} Whether the file is valid
 */
export function verifyNyxEncFileIntegrity(
  nyxEncFile: NyxEncFile,
  encryptionKey: string
): boolean {
  try {
    const contentForSigning = JSON.stringify({
      version: nyxEncFile.version,
      metadata: nyxEncFile.metadata,
      encryptedContent: nyxEncFile.encryptedContent
    });
    
    const expectedSignature = CryptoJS.HmacSHA256(contentForSigning, encryptionKey).toString();
    return constantTimeCompare(expectedSignature, nyxEncFile.signature);
  } catch {
    return false;
  }
}

/**
 * Check if a .nyxenc file has expired
 * @param {NyxEncFileMetadata} metadata - File metadata
 * @returns {object} Expiration status
 */
export function isNyxEncFileExpired(metadata: NyxEncFileMetadata): {
  isExpired: boolean;
  timeRemaining?: string;
  expiresAt: string;
} {
  try {
    const now = new Date();
    const expiresAt = new Date(metadata.expiresAt);
    const isExpired = now > expiresAt;
    
    if (isExpired) {
      return {
        isExpired: true,
        expiresAt: metadata.expiresAt
      };
    }
    
    // Calculate remaining time
    const diff = expiresAt.getTime() - now.getTime();
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
    const hours = Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
    
    let timeRemaining = '';
    if (days > 0) {
      timeRemaining = `${days}d ${hours}h remaining`;
    } else if (hours > 0) {
      timeRemaining = `${hours}h ${minutes}m remaining`;
    } else {
      timeRemaining = `${minutes}m remaining`;
    }
    
    return {
      isExpired: false,
      timeRemaining,
      expiresAt: metadata.expiresAt
    };
  } catch {
    // If date parsing fails, assume expired for security
    return {
      isExpired: true,
      expiresAt: metadata.expiresAt || 'Invalid date'
    };
  }
}

/**
 * Constant-time string comparison to prevent timing attacks
 * @param {string} a - First string
 * @param {string} b - Second string
 * @returns {boolean} Whether strings match
 */
function constantTimeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

/**
 * Derive deterministic encryption key from metadata
 * @param {NyxEncFileMetadata} metadata - File metadata
 * @param {string} fileVersion - File format version
 * @returns {string} Derived encryption key
 */
export function deriveDeterministicKey(
  metadata: NyxEncFileMetadata,
  fileVersion: string = NYXENC_VERSION
): string {
  const walletAddress = metadata.encryptionWallet;
  const createdAt = metadata.createdAt;
  const planType = metadata.planType;
  const version = fileVersion;
  const title = metadata.title || '';
  const securityNonce = metadata.securityNonce || '';
  
  // Enhanced key material with nonce
  const keyMaterial = securityNonce 
    ? `${walletAddress}:${createdAt}:${planType}:${version}:${title}:${securityNonce}`
    : `${walletAddress}:${createdAt}:${planType}:${version}:${title}`;
  
  // Dynamic salt
  const fileSalt = securityNonce
    ? CryptoJS.SHA256(`nyxenc-v${version}-${planType}-${walletAddress}-${securityNonce}`).toString().substring(0, 32)
    : `nyxenc-v${version}-${planType}`;
  
  // Enhanced PBKDF2 parameters
  const iterations = securityNonce ? 100000 : 10000;
  
  const derivedKey = CryptoJS.PBKDF2(keyMaterial, fileSalt, {
    keySize: 256 / 32,
    iterations: iterations,
    hasher: CryptoJS.algo.SHA256
  });
  
  return derivedKey.toString();
}

/**
 * Validate a Solana public key
 * @param {string} publicKey - Public key to validate
 * @returns {boolean} Whether key is valid
 */
export function isValidPublicKey(publicKey: string): boolean {
  try {
    new PublicKey(publicKey);
    return true;
  } catch {
    return false;
  }
}

/**
 * Verify a wallet signature
 * @param {string} messageContent - Original message
 * @param {string} messageSignature - Ed25519 signature
 * @param {string} walletPublicKey - Wallet public key
 * @returns {Promise<boolean>} Whether signature is valid
 */
export async function verifySignature(
  messageContent: string,
  messageSignature: string,
  walletPublicKey: string
): Promise<boolean> {
  try {
    const messageBytes = new TextEncoder().encode(messageContent);
    const signatureBytes = bs58.decode(messageSignature);
    const publicKeyBytes = bs58.decode(walletPublicKey);
    return await verify(signatureBytes, messageBytes, publicKeyBytes);
  } catch {
    return false;
  }
}

/**
 * Derive a secure key for paid content using payment proof
 */
export function deriveSecurePaidKey(
  metadata: NyxEncFileMetadata,
  paymentProof: string,
  fileVersion: string = NYXENC_VERSION
): string {
  if (!metadata.isPaid) {
    return deriveDeterministicKey(metadata, fileVersion);
  }
  if (!paymentProof) {
    throw new Error('Payment proof required for paid content decryption');
  }
  const {
    encryptionWallet,
    createdAt,
    planType,
    title = '',
    contentId = '',
    priceAmount = 0,
    securityNonce = ''
  } = metadata;

  const paidKeyMaterial = securityNonce
    ? `PAID:${encryptionWallet}:${createdAt}:${planType}:${fileVersion}:${title}:${contentId}:${priceAmount}:${paymentProof}:${securityNonce}`
    : `PAID:${encryptionWallet}:${createdAt}:${planType}:${fileVersion}:${title}:${contentId}:${priceAmount}:${paymentProof}`;

  const paidSalt = CryptoJS.SHA256(`nyxenc-paid-v${fileVersion}-${contentId}-${paymentProof}`).toString().substring(0, 32);
  const iterations = 150000;
  const derivedKey = CryptoJS.PBKDF2(paidKeyMaterial, paidSalt, {
    keySize: 256 / 32,
    iterations,
    hasher: CryptoJS.algo.SHA256
  });
  return derivedKey.toString();
}

/**
 * Derive a key using blockchain memo metadata (sender/recipient/memo)
 */
export function deriveBlockchainKey(
  metadata: NyxEncFileMetadata,
  fileVersion: string = NYXENC_VERSION
): string {
  const {
    recipientWallet,
    chainTxMemo,
    chainTxTime,
    planType,
    title = '',
    securityNonce = ''
  } = metadata;
  if (!recipientWallet || !chainTxMemo || !chainTxTime) {
    throw new Error('Missing blockchain memo fields for key derivation');
  }
  const keyMaterial = securityNonce
    ? `${recipientWallet}:${chainTxMemo}:${chainTxTime}:${planType}:${fileVersion}:${title}:${securityNonce}`
    : `${recipientWallet}:${chainTxMemo}:${chainTxTime}:${planType}:${fileVersion}:${title}`;
  const salt = securityNonce
    ? CryptoJS.SHA256(`nyxenc-blockchain-v${fileVersion}-${planType}-${recipientWallet}-${securityNonce}`).toString().substring(0, 32)
    : `nyxenc-blockchain-v${fileVersion}-${planType}-${recipientWallet}`;
  const iterations = securityNonce ? 150000 : 50000;
  const derivedKey = CryptoJS.PBKDF2(keyMaterial, salt, {
    keySize: 256 / 32,
    iterations,
    hasher: CryptoJS.algo.SHA256
  });
  return derivedKey.toString();
}

/**
 * Generate a unique memo string for blockchain transactions
 */
export function generateBlockchainMemo(contentId?: string, title?: string): string {
  const timestamp = Date.now();
  const randomSuffix = Math.random().toString(36).substring(2, 8);
  if (contentId) {
    return `NYXENC:${contentId}:${timestamp}:${randomSuffix}`;
  }
  if (title) {
    const sanitized = title.replace(/[^a-zA-Z0-9]/g, '').substring(0, 10);
    return `NYXENC:${sanitized}:${timestamp}:${randomSuffix}`;
  }
  return `NYXENC:CONTENT:${timestamp}:${randomSuffix}`;
}

/**
 * Create a memo-only Solana transaction (no SOL transfer)
 */
export async function createBlockchainMemoTransaction(
  provider: any,
  recipientWallet: string,
  memo: string
): Promise<{ success: boolean; transactionHash?: string; timestamp?: string; error?: string }> {
  try {
    if (!provider?.publicKey) throw new Error('Wallet not connected');
    new PublicKey(recipientWallet); // validate
    const endpoints = [
      'https://api.mainnet-beta.solana.com',
      'https://rpc.ankr.com/solana'
    ];
    let connection: Connection | null = null;
    for (const ep of endpoints) {
      try {
        connection = new Connection(ep, 'confirmed');
        await connection.getLatestBlockhash('confirmed');
        break;
      } catch {
        connection = null;
        continue;
      }
    }
    if (!connection) throw new Error('Unable to connect to Solana RPC');
    const tx = new Transaction();
    tx.feePayer = provider.publicKey;
    tx.add(createMemoInstruction(memo, [provider.publicKey]));
    const { blockhash } = await connection.getLatestBlockhash('confirmed');
    tx.recentBlockhash = blockhash;
    const resp = await provider.signAndSendTransaction(tx, { skipPreflight: false, preflightCommitment: 'confirmed' });
    const sig = resp.signature || resp; // wallet adapter variants
    await connection.confirmTransaction(sig, 'confirmed');
    const details = await connection.getTransaction(sig, { commitment: 'confirmed', maxSupportedTransactionVersion: 0 });
    const ts = details?.blockTime ? new Date(details.blockTime * 1000).toISOString() : new Date().toISOString();
    return { success: true, transactionHash: sig, timestamp: ts };
  } catch (err: any) {
    return { success: false, error: err.message || 'Failed to create memo transaction' };
  }
}

/**
 * Verify a memo transaction exists on-chain and matches expectations
 */
export async function verifyBlockchainMemoTransaction(
  transactionHash: string,
  expectedMemo: string,
  expectedSender: string
): Promise<{ valid: boolean; timestamp?: string; error?: string }> {
  try {
    const connection = new Connection('https://api.mainnet-beta.solana.com', 'confirmed');
    const tx = await connection.getTransaction(transactionHash, { commitment: 'confirmed', maxSupportedTransactionVersion: 0 });
    if (!tx) return { valid: false, error: 'Transaction not found' };
    if (tx.meta?.err) return { valid: false, error: 'Transaction failed' };
    const accountKeys = tx.transaction.message.getAccountKeys ? 
      tx.transaction.message.getAccountKeys() : 
      (tx.transaction.message as any).accountKeys;
    const sender = accountKeys[0]?.toString();
    if (sender !== expectedSender) return { valid: false, error: 'Sender wallet mismatch' };
          const memoPresent = tx.meta?.logMessages?.some((l: string) => l.includes(expectedMemo));
    if (!memoPresent) return { valid: false, error: 'Expected memo not found' };
    const ts = tx.blockTime ? new Date(tx.blockTime * 1000).toISOString() : undefined;
    return { valid: true, timestamp: ts };
  } catch (err: any) {
    return { valid: false, error: err.message };
  }
}

/**
 * Generate a secure filename for .nyxenc downloads
 */
export function generateSecureFilename(customTitle?: string): string {
  /* eslint-disable-next-line no-control-regex */
  let filename = customTitle?.trim().replace(/[<>:"/\\|?*\x00-\x1f]/g, '').replace(/\.nyxenc$/i, '') || `encrypted-${Date.now()}`;
  filename = filename.substring(0, 50);
  return `${filename}.nyxenc`;
}

/**
 * Trigger download of a .nyxenc file in the browser
 */
export function downloadNyxEncFile(nyxEncFile: NyxEncFile, filename: string): void {
  const blob = new Blob([JSON.stringify(nyxEncFile, null, 2)], { type: 'application/json' });
  if ('showSaveFilePicker' in window) {
    // modern browsers
    (async () => {
      // @ts-expect-error showSaveFilePicker is experimental and not yet in the DOM lib
      const handle = await window.showSaveFilePicker({ suggestedName: filename });
      const writable = await handle.createWritable();
      await writable.write(blob);
      await writable.close();
    })().catch(() => downloadWithFallback(blob, filename));
  } else {
    downloadWithFallback(blob, filename);
  }
}

function downloadWithFallback(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
} 