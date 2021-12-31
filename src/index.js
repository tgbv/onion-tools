import base32Decode from "base32-decode";
import { createHash } from "crypto";

/**
 * IETF base32 specification used by onion addresses.
 * 
 * @see https://datatracker.ietf.org/doc/html/rfc3548
 */
export const base32Variant = "RFC3548";

/**
 * Base32 alphabet variant used by onion addresses. Defined by RFC3548.
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
 * Use to check if onion address is valid or not. Only V3 adresses are supported.
 * 
 * Example: facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion
 * 
 * @param {string} address
 * @returns {boolean} valid or not
 */
export function isValidV3OnionAddress(address) {
  address = address.toString().toUpperCase();

  if (address.match(new RegExp(`^[${base32AlphabetVariant}]{56}\\.ONION$`))) {
    address = address.replace('.ONION', '');

    const decodedAddress = base32Decode(address, base32Variant);
    const pureAddress = Buffer.from(decodedAddress.slice(0, 32));
    const addressChecksum = Buffer.from(decodedAddress.slice(32, 34));
    const addressVersion = Buffer.from(decodedAddress.slice(34));

    if (addressVersion.toString('hex') === '03') {
      const computedChecksum = computeV3Checksum(pureAddress);
      const hashedChecksum = createHash("sha3-256").update(computedChecksum);

      return hashedChecksum.digest('hex').startsWith(addressChecksum.toString('hex'));
    }
  }

  return false;
}
