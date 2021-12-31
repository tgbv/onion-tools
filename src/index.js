import base32Decode from "base32-decode";
import { createHash } from "crypto";

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
 * Computes a V3 public key checksum.
 * 
 * @param {Buffer} publicKey 
 * @returns {Buffer}
 */
function computeV3Checksum(publicKey) {
  return Buffer.concat([
    Buffer.from(".onion checksum", "ascii"),
    publicKey,
    new Uint8Array([3])
  ]);
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
  domain = domain.toString().toUpperCase();

  if (domain.match(new RegExp(`^[${base32AlphabetVariant}]{56}\\.ONION$`))) {
    domain = domain.replace('.ONION', '');

    const decodedDomain = base32Decode(domain, base32Variant);
    const pureDomain = Buffer.from(decodedDomain.slice(0, 32));
    const domainChecksum = Buffer.from(decodedDomain.slice(32, 34));
    const domainVersion = Buffer.from(decodedDomain.slice(34));

    if (domainVersion.toString('hex') === '03') {
      const computedChecksum = computeV3Checksum(pureDomain);
      const hashedChecksum = createHash("sha3-256").update(computedChecksum);

      return hashedChecksum.digest('hex').startsWith(domainChecksum.toString('hex'));
    }
  }

  return false;
}
