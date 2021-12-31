import { isValidV3OnionDomain } from "../index.js";
import assert from "assert";

const valid = "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion";
const invalidChecksum = "zacebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion";
const invalidRegexVariants = [
  "facebookwkhpilnemxj7ahye3mhbshg7kx5tfyd.onion",
  "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd",
  "facebook1wkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfy.onion",
  "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyonion",
  "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfy . onion",
  "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfy.onion  ",
  "facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfy.onio",
];

it('should pass on valid domain', () => {
  const result = isValidV3OnionDomain(valid);
  assert.equal(result, true);
});

it('should pass on invalid domain syntax', () => {
  let result = false;

  for (const variant of invalidRegexVariants) {
    if (isValidV3OnionDomain(variant)) {
      result = true;
      break;
    }
  }

  assert.equal(result, false);
});

it('should pass on invalid domain checksum', () => {
  const result = isValidV3OnionDomain(invalidChecksum);
  assert.equal(result, false);
});
