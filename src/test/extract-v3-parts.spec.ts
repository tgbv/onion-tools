import { extractV3Parts } from "../index";

const domain = "ciadotgov4sjwlzihbbgxnqg3xiyrg7so2r2o3lt5wz5ypk4sxyjstad.onion";
const domainInvalid = "xciadotgov4sjwlzihbbgxnqg3xiyrg7so2r2o3lt5wz5ypk4sxyjstad.onion";

it("should pass on extracting bones of a valid domain", function () {
  let result = true;

  try {
    extractV3Parts(domain);
  } catch (e) {
    result = false;
  }

  expect(result).toBe(true);
});

it("should pass on extracting bones of an invalid domain", function () {
  let result = false;

  try {
    extractV3Parts(domainInvalid);
  } catch (e) {
    result = true;
  }

  expect(result).toBe(true);
});

it("should pass on extracting correct bones of a valid domain", function () {
  let result = {};

  try {
    result = extractV3Parts(domain);
  } catch (e) { }

  expect(result).toHaveProperty("publicKey");
  expect(result).toHaveProperty("checksum");
  expect(result).toHaveProperty("version");
});
