import base32Decode from "base32-decode";
import { createHash } from "crypto";
import { InvalidSyntax } from "./exceptions.js";

/**
 * IETF base32 specification used by onion domains.
 * 
 * @see https://datatracker.ietf.org/doc/html/rfc3548
 */
export const base32Variant = "RFC3548";

/**
 * Base32 alphabet variant used by onion domains. Defined by RFC3548.
 * 
 * @see base32Variant
 */
export const base32AlphabetVariant = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/**
 * V3 domain checksum salt.
 * 
 * @type {Buffer}
 */
export const v3ChecksumSalt = Buffer.from(".onion checksum", "ascii");

/**
 * V3 domain checksum version.
 * 
 * @type {Buffer}
 */
export const v3ChecksumVersion = Buffer.from(new Uint8Array([3]));

/**
 * Computes a V3 public key checksum.
 * 
 * @param {Buffer} publicKey
 * @returns {Buffer} Buffer holding the first 2 bytes of the hashed checksum data. 
 */
function computeV3Checksum(publicKey) {
  const checksumBuff = Buffer.concat([
    v3ChecksumSalt,
    publicKey,
    v3ChecksumVersion
  ]);

  const checksumHash = createHash("sha3-256").update(checksumBuff);

  return checksumHash.digest().slice(0, 2);
}

/**
 * @param {string} domain
 * @returns {string}
 */
function sanitizeDomainForInternalUse(domain) {
  domain = domain.toUpperCase();

  return domain.replace('.ONION', '');
}

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
export function isValidV3OnionDomainSyntax(domain) {
  domain = domain.toUpperCase();

  return domain.match(new RegExp(`^[${base32AlphabetVariant}]{56}\\.ONION$`));
}

/**
 * Extract 'bones' from a V3 domain.
 * 
 * @param {string} domain
 * @returns {{
 *  publicKey: Buffer,
 *  checksum: Buffer,
 *  version: Buffer,
 * }}
 * @throws {InvalidSyntax} in case input domain has an invalid syntax.
 */
export function extractV3Bones(domain) {

  if (isValidV3OnionDomainSyntax(domain)) {
    domain = sanitizeDomainForInternalUse(domain);

    const decodedDomain = base32Decode(domain, base32Variant);

    return {
      publicKey: Buffer.from(decodedDomain.slice(0, 32)),
      checksum: Buffer.from(decodedDomain.slice(32, 34)),
      version: Buffer.from(decodedDomain.slice(34))
    }
  }

  throw InvalidSyntax;
}

/**
 * Use to check if onion domain is valid or not. Only V3 domains are supported.
 * 
 * Example: facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion
 * 
 * @param {string} domain
 * @returns {boolean} valid or not
 */
export function isValidV3OnionDomain(domain) {

  if (isValidV3OnionDomainSyntax(domain)) {
    const { publicKey, checksum, version } = extractV3Bones(domain);

    if (version.equals(v3ChecksumVersion)) {
      return computeV3Checksum(publicKey).equals(checksum);
    }
  }

  return false;
}
