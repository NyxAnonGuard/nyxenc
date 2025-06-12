import {
  encryptContent,
  decryptContent,
  generateEncryptionKey,
  generateNyxEncFile,
  validateNyxEncFile,
  verifyNyxEncFileIntegrity,
  deriveSecurePaidKey,
  generateBlockchainMemo
} from '../src';

describe('NyxEnc Encryption', () => {
  const testContent = 'Hello, World!';
  const testWallet = '7v91N7iuxY3xV5RbGP1YJwXNkV4YzXn2pKhZhWPu7Pv6'; // Example Solana address

  describe('Basic Encryption/Decryption', () => {
    it('should encrypt and decrypt content correctly', () => {
      const key = generateEncryptionKey();
      const encrypted = encryptContent(testContent, key);
      const decrypted = decryptContent(encrypted, key);
      expect(decrypted).toBe(testContent);
    });

    it('should handle JSON content', () => {
      const key = generateEncryptionKey();
      const jsonContent = { message: testContent };
      const encrypted = encryptContent(JSON.stringify(jsonContent), key);
      const decrypted = decryptContent(encrypted, key);
      expect(JSON.parse(decrypted)).toEqual(jsonContent);
    });

    it('should fail with wrong key', () => {
      const key1 = generateEncryptionKey();
      const key2 = generateEncryptionKey();
      const encrypted = encryptContent(testContent, key1);
      expect(() => decryptContent(encrypted, key2)).toThrow();
    });
  });

  describe('.nyxenc File Generation', () => {
    const metadata = {
      encryptionWallet: testWallet,
      planType: 'free' as const,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      duration: '1d',
      isPaid: false
    };

    it('should generate valid .nyxenc files', () => {
      const key = generateEncryptionKey();
      const encrypted = encryptContent(testContent, key);
      const file = generateNyxEncFile(encrypted, metadata, key);
      
      expect(file.version).toBeDefined();
      expect(file.metadata).toEqual(expect.objectContaining(metadata));
      expect(file.encryptedContent).toBeDefined();
      expect(file.signature).toBeDefined();
    });

    it('should validate .nyxenc files', () => {
      const key = generateEncryptionKey();
      const encrypted = encryptContent(testContent, key);
      const file = generateNyxEncFile(encrypted, metadata, key);
      
      const validation = validateNyxEncFile(JSON.stringify(file));
      expect(validation.valid).toBe(true);
      expect(validation.file).toBeDefined();
    });

    it('should verify file integrity', () => {
      const key = generateEncryptionKey();
      const encrypted = encryptContent(testContent, key);
      const file = generateNyxEncFile(encrypted, metadata, key);
      
      expect(verifyNyxEncFileIntegrity(file, key)).toBe(true);
    });

    it('should detect tampered files', () => {
      const key = generateEncryptionKey();
      const encrypted = encryptContent(testContent, key);
      const file = generateNyxEncFile(encrypted, metadata, key);
      
      // Tamper with content
      const tamperedFile = {
        ...file,
        encryptedContent: encryptContent('Tampered content', key)
      };
      
      expect(verifyNyxEncFileIntegrity(tamperedFile, key)).toBe(false);
    });
  });

  describe('Paid Content', () => {
    const paidMetadata = {
      encryptionWallet: testWallet,
      planType: 'pro' as const,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      duration: '1d',
      isPaid: true,
      priceAmount: 0.1,
      contentId: 'test-content-123'
    };

    it('should derive different keys for different payment proofs', () => {
      const proof1 = 'tx-hash-1';
      const proof2 = 'tx-hash-2';
      
      const key1 = deriveSecurePaidKey(paidMetadata, proof1);
      const key2 = deriveSecurePaidKey(paidMetadata, proof2);
      
      expect(key1).not.toBe(key2);
    });

    it('should require payment proof for paid content', () => {
      expect(() => deriveSecurePaidKey(paidMetadata, '')).toThrow();
    });
  });

  describe('Blockchain Integration', () => {
    it('should generate unique memos', () => {
      const memo1 = generateBlockchainMemo('content-1');
      const memo2 = generateBlockchainMemo('content-1');
      expect(memo1).not.toBe(memo2);
    });

    it('should include content ID in memo', () => {
      const contentId = 'test-123';
      const memo = generateBlockchainMemo(contentId);
      expect(memo).toContain(contentId);
    });
  });
}); 