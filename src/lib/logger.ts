// Simple logger wrapper for NyxEnc public library
export const logger = {
  info: (...args: unknown[]) => console.info('[NyxEnc]', ...args),
  warn: (...args: unknown[]) => console.warn('[NyxEnc]', ...args),
  error: (...args: unknown[]) => console.error('[NyxEnc]', ...args)
}; 