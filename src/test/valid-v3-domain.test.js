import { isValidV3OnionDomain, isValidV3OnionDomainSyntax } from "../index.js";
import assert from "assert";

const valid = "ciadotgov4sjwlzihbbgxnqg3xiyrg7so2r2o3lt5wz5ypk4sxyjstad.onion";
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
    if (isValidV3OnionDomainSyntax(variant)) {
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
