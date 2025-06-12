import { 
  encryptContent, 
  generateNyxEncFile, 
  generateEncryptionKey,
  validateNyxEncFile,
  decryptContent
} from '../src';

// Example 1: Basic Encryption
async function basicEncryption() {
  // Generate a random encryption key
  const key = generateEncryptionKey();
  
  // Content to encrypt
  const content = "Hello, this is a secret message!";
  
  // Encrypt the content
  const encrypted = encryptContent(content, key);
  
  // Create metadata
  const metadata = {
    encryptionWallet: "your-solana-wallet-address",
    planType: "free" as const,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(), // 24 hours
    duration: "1d",
    isPaid: false
  };
  
  // Generate .nyxenc file
  const nyxEncFile = generateNyxEncFile(encrypted, metadata, key);
  
  console.log('Generated .nyxenc file:', {
    version: nyxEncFile.version,
    metadata: nyxEncFile.metadata,
    signatureLength: nyxEncFile.signature.length
  });
  
  // Validate the file
  const validation = validateNyxEncFile(JSON.stringify(nyxEncFile));
  console.log('File validation:', validation.valid);
  
  // Decrypt the content
  if (validation.valid && validation.file) {
    const decrypted = decryptContent(validation.file.encryptedContent, key);
    console.log('Decrypted content:', decrypted);
  }
}

// Run the example
basicEncryption().catch(console.error); 