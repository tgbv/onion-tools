import { InvalidSyntax } from "./exceptions";

/**
 * IETF base32 specification used by onion domains.
 * 
 * @see https://datatracker.ietf.org/doc/html/rfc3548
 */
export declare const base32Variant: string;

/**
 * Base32 alphabet variant used by onion domains. Defined by RFC3548.
 * 
 * @see base32Variant
 */
export declare const base32AlphabetVariant: string;

/**
 * V3 domain checksum salt.
 */
export declare const v3ChecksumSalt: Buffer;

/**
 * V3 domain checksum version.
 */
export declare const v3ChecksumVersion: Buffer;

/**
 * Header used by Tor onion service public key file.
 */
export declare const v3ServicePubKeyHeader: Buffer;

/**
 * Header used by Tor onion service private key file.
 */
export declare const v3ServicePrivKeyHeader: Buffer;

/**
 * Computes a V3 public key checksum.
 * 
 * @param {Buffer} publicKey
 * @returns {Buffer} Buffer holding the first 2 bytes of the hashed checksum data. 
 */
export declare function computeV3Checksum(publicKey: Buffer): Buffer;


declare function sanitizeDomainForInternalUse(domain: string): string;
declare function computeExpandedPrivateKeyFromSeed(seed: Buffer): Buffer;
declare function sanitizePubKeyForHiddenServiceHosting(key: Buffer): Buffer;
declare function sanitizeExpandedPrivKeyForHiddenServiceHosting(expandedPrivKey: Buffer): Buffer;

/**
 * Use this to check if onion domain has the correct syntax.
 * 
 * Note this only validates the syntax, not the checksum.
 * To fully check if a domain is valid use 'isValidV3OnionDomain(domain)'.
 * 
 * Example: facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion
 * 
 * @param {string} domain 
 * @returns {boolean} valid or not
 * 
 * @see isValidV3OnionDomain
 */
export declare function isValidV3OnionDomainSyntax(domain: string): boolean;

/**
 * Bones / parts which compose an onion domain.
 */
export declare interface IV3DomainBones {
  /**
   * Domain's public key.
   */
  publicKey: Buffer;

  /**
   * Domain's checksum.
   */
  checksum: Buffer;

  /**
   * Domain's version.
   */
  version: Buffer;
}

/**
 * Extract 'bones' from a V3 domain.
 * 
 * @throws {InvalidSyntax} in case input domain has an invalid syntax.
 */
export declare function extractV3Bones(domain: string): IV3DomainBones;

/**
 * Use to check if onion domain is valid or not. Only V3 domains are supported.
 * 
 * Example: facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion
 * 
 * @param {string} domain
 * @returns {boolean} valid or not
 */
export declare function isValidV3OnionDomain(domain: string): boolean;

/**
 * V3 domain metadata.
 */
export declare interface IV3DomainMeta {

  /**
   * The expanded private key of the domain.
   */
  expandedPrivateKey: Buffer;

  /**
   * Domain's public key, derived from the expanded private key.
   */
  publicKey: Buffer;

  /**
   * Actual generated domain. Example: facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion
   */
  domain: string;
}

/**
 * Generate a V3 onion domain.
 * 
 * If seed is specified, seed will be fed into a sha256 digest which will be used to compute the private key.
 * Otherwise a random seed with a random private key will be generated.
 * 
 * Note that by default the private/public keys pair cannot be directly exported to files
 * for Tor hidden service hosting. To sanitize them for that feature see 'formatForService' parameter.
 * 
 * @param {?any} seed Can contain anything. Will be fed into a sha256 digest.
 * Should be long enough for security reasons. If it's null/undefined, a random seed will be used.
 * If it's specified, the whole generation process will be deterministic.
 * 
 * @param {boolean} formatForService Set to true if you want to format the public/private keys
 * in a syntax ready to be imported by Tor hidden service hosting.
 * 
 * @returns {Promise<IV3DomainMeta>}
 */
export declare async function generateV3OnionDomain(seed?: string | ArrayBufferView, formatForService: boolean = false): Promise<IV3DomainMeta>;
