/**
 * Core types for the NyxEnc encryption system.
 * @module types
 */

/**
 * Metadata for a .nyxenc file
 */
export interface NyxEncFileMetadata {
  /** Optional title of the encrypted content */
  title?: string;
  
  /** Solana wallet address that can decrypt the content */
  encryptionWallet: string;
  
  /** Type of plan (free, holder, pro) */
  planType: 'free' | 'holder' | 'pro';
  
  /** ISO timestamp when the content was created */
  createdAt: string;
  
  /** ISO timestamp when the content expires */
  expiresAt: string;
  
  /** Duration string (e.g., '1d', '1w') */
  duration: string;
  
  /** Whether this content requires payment */
  isPaid: boolean;
  
  /** Price in SOL (only if isPaid is true) */
  priceAmount?: number;
  
  /** Reference to backend database record */
  contentId?: string;
  
  /** Temporary placeholder until real payment is made */
  paymentPlaceholder?: string;
  
  /** 32-byte random nonce for enhanced security */
  securityNonce?: string;
  
  /** Whether this file uses blockchain memo verification */
  isBlockchainSigned?: boolean;
  
  /** Sender wallet that signed the transaction */
  senderWallet?: string;
  
  /** Recipient wallet that can decrypt the content */
  recipientWallet?: string;
  
  /** Unique memo from blockchain transaction */
  chainTxMemo?: string;
  
  /** Blockchain transaction hash */
  chainTxHash?: string;
  
  /** Blockchain transaction timestamp */
  chainTxTime?: string;
}

/**
 * Structure of a .nyxenc file
 */
export interface NyxEncFile {
  /** Version of the .nyxenc format */
  version: string;
  
  /** Metadata about the encrypted content */
  metadata: NyxEncFileMetadata;
  
  /** The encrypted content (AES-256) */
  encryptedContent: string;
  
  /** HMAC-SHA256 signature for integrity verification */
  signature: string;
}

/**
 * Result of file validation
 */
export interface ValidationResult {
  /** Whether the file is valid */
  valid: boolean;
  
  /** Error message if validation failed */
  error?: string;
  
  /** The validated file if successful */
  file?: NyxEncFile;
}

/**
 * Result of key extraction
 */
export interface KeyExtractionResult {
  /** Whether key extraction was successful */
  success: boolean;
  
  /** The extracted encryption key */
  encryptionKey?: string;
  
  /** Error message if extraction failed */
  error?: string;
  
  /** Information about file expiration */
  expirationInfo?: {
    isExpired: boolean;
    timeRemaining?: string;
    expiresAt: string;
  };
}

/**
 * Payment verification result
 */
export interface PaymentVerificationResult {
  /** Whether payment is valid */
  canDecrypt: boolean;
  
  /** Reason for the result */
  reason: string;
  
  /** Status of the transaction */
  transaction_status?: string;
}

/**
 * Blockchain transaction result
 */
export interface BlockchainTransactionResult {
  /** Whether transaction was successful */
  success: boolean;
  
  /** Transaction hash if successful */
  transactionHash?: string;
  
  /** Transaction timestamp */
  timestamp?: string;
  
  /** Error message if failed */
  error?: string;
} 