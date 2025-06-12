import { 
  encryptContent,
  generateNyxEncFile,
  generateEncryptionKey,
  deriveSecurePaidKey,
  decryptContent,
  generateBlockchainMemo,
  createBlockchainMemoTransaction
} from '../src';

// Example: Paid Content with Blockchain Verification
async function paidContentExample() {
  // 1. Content Owner: Encrypt the content
  const key = generateEncryptionKey();
  const content = "This is premium content that requires payment!";
  const encrypted = encryptContent(content, key);
  
  // 2. Create metadata with payment requirement
  const metadata = {
    encryptionWallet: "content-owner-wallet",
    planType: "pro" as const,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(), // 7 days
    duration: "7d",
    isPaid: true,
    priceAmount: 0.1, // 0.1 SOL
    contentId: "unique-content-id",
    securityNonce: generateEncryptionKey() // Extra security
  };
  
  // 3. Generate .nyxenc file
  const nyxEncFile = generateNyxEncFile(encrypted, metadata, key);
  console.log('Generated paid content file:', {
    contentId: metadata.contentId,
    price: metadata.priceAmount,
    expiresAt: metadata.expiresAt
  });
  
  // 4. Buyer: After payment, verify and decrypt
  // Simulate payment transaction
  const paymentTxHash = "simulated-blockchain-tx-hash";
  
  // 5. Derive key using payment proof
  const buyerKey = deriveSecurePaidKey(metadata, paymentTxHash);
  
  // 6. Decrypt the content
  const decrypted = decryptContent(nyxEncFile.encryptedContent, buyerKey);
  console.log('Decrypted paid content:', decrypted);
  
  // 7. Optional: Create blockchain memo
  const memo = generateBlockchainMemo(metadata.contentId);
  console.log('Blockchain memo:', memo);
  
  // 8. Optional: Record on blockchain (requires wallet)
  /*
  const provider = window.solana; // or other wallet
  const result = await createBlockchainMemoTransaction(
    provider,
    metadata.encryptionWallet,
    memo
  );
  console.log('Blockchain record:', result);
  */
}

// Run the example
paidContentExample().catch(console.error); 