import assert from "assert";
import { should } from "chai";
import { extractV3Bones } from "../index.js";

should();

const domain = "ciadotgov4sjwlzihbbgxnqg3xiyrg7so2r2o3lt5wz5ypk4sxyjstad.onion";
const domainInvalid = "xciadotgov4sjwlzihbbgxnqg3xiyrg7so2r2o3lt5wz5ypk4sxyjstad.onion";

it("should pass on extracting bones of a valid domain", function () {
  let result = true;

  try {
    extractV3Bones(domain);
  } catch (e) {
    result = false;
  }

  assert.equal(result, true);
});

it("should pass on extracting bones of an invalid domain", function () {
  let result = false;

  try {
    extractV3Bones(domainInvalid);
  } catch (e) {
    result = true;
  }

  assert.equal(result, true);
});

it("should pass on extracting correct bones of a valid domain", function () {
  let result = {};

  try {
    result = extractV3Bones(domain);
  } catch (e) { }

  result.should.contain.keys(["publicKey", "checksum", "version"]);
});
