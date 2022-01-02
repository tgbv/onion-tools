import base32Decode from "base32-decode";
import base32Encode from "base32-encode";
import { createHash } from "crypto";
import { InvalidSyntax } from "./exceptions.js";
import * as ed25519 from "noble-ed25519";

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
 * Header used by Tor onion service public key file.
 */
export const v3ServicePubKeyHeader = Buffer.from("== ed25519v1-public: type0 ==\x00\x00\x00");

/**
 * Header used by Tor onion service private key file.
 */
export const v3ServicePrivKeyHeader = Buffer.from("== ed25519v1-secret: type0 ==\x00\x00\x00");

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
 * @param {Buffer} seed 
 * @returns {Buffer}
 */
function computeExpandedPrivateKeyFromSeed(seed) {
  const privKeyHashBuff = createHash("sha512").update(seed).digest();

  privKeyHashBuff.set([privKeyHashBuff[0] & 248], 0);
  privKeyHashBuff.set([privKeyHashBuff[31] & 127], 31);
  privKeyHashBuff.set([privKeyHashBuff[31] | 64], 31);

  return privKeyHashBuff;
}

/**
 * @param {Buffer} key 
 * @returns {Buffer}
 */
function sanitizePubKeyForHiddenServiceHosting(key) {
  return Buffer.concat([
    v3ServicePubKeyHeader,
    key
  ]);
}

/**
 * @param {Buffer} expandedPrivKey 
 * @returns {Buffer}
 */
function sanitizeExpandedPrivKeyForHiddenServiceHosting(expandedPrivKey) {
  return Buffer.concat([
    v3ServicePrivKeyHeader,
    expandedPrivKey
  ]);
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
 * @returns {Promise<{
 *  expandedPrivateKey: Buffer,
 *  publicKey: Buffer,
 *  domain: string,
 * }>} Domain meta.
 */
export async function generateV3OnionDomain(seed, formatForService = false) {
  const privateSeed = seed ? createHash("sha256").update(seed).digest() : ed25519.utils.randomPrivateKey();
  const publicKey = Buffer.from(await ed25519.getPublicKey(privateSeed));

  const domainPure = Buffer.concat([
    publicKey,
    computeV3Checksum(publicKey),
    v3ChecksumVersion
  ]);

  const domainEncoded = base32Encode(domainPure, base32Variant);

  const expandedPrivateKey = computeExpandedPrivateKeyFromSeed(privateSeed);

  return {
    expandedPrivateKey: formatForService ? sanitizeExpandedPrivKeyForHiddenServiceHosting(expandedPrivateKey) : expandedPrivateKey,
    publicKey: formatForService ? sanitizePubKeyForHiddenServiceHosting(publicKey) : publicKey,
    domain: domainEncoded.toLowerCase() + ".onion"
  }
}
