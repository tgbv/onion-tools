import { generateV3OnionDomain, isValidV3OnionDomain } from "../index.js";
import { should } from "chai";
import assert from "assert";

should();

/**
 * Helper function for asserting domain meta.
 * 
 * @param {*} domainMeta 
 */
function assertDomainMeta(domainMeta) {
  domainMeta.should.contain.keys("publicKey", "expandedPrivateKey", "domain");
  domainMeta.publicKey.should.length(32);
  domainMeta.expandedPrivateKey.should.length(64);

  assert.equal(isValidV3OnionDomain(domainMeta.domain), true);
}

/**
 * Helper function for asserting domain meta.
 * 
 * @param {*} domainMeta 
 */
function assertDomainMetaServiceSanitized(domainMeta) {
  domainMeta.should.contain.keys("publicKey", "expandedPrivateKey", "domain");
  domainMeta.publicKey.should.length(64);
  domainMeta.expandedPrivateKey.should.length(96);

  assert.equal(isValidV3OnionDomain(domainMeta.domain), true);
}

it("should pass on random domain generation", async function () {
  let result = await generateV3OnionDomain();

  assertDomainMeta(result);
});

it("should pass on random domain generation with sanitization for onion service import", async function () {
  let result = await generateV3OnionDomain(null, true);

  assertDomainMetaServiceSanitized(result);
});

it("should pass on seeded domain generation", async function () {
  let domain1 = await generateV3OnionDomain("seed one");
  let domain2 = await generateV3OnionDomain("seed two");

  assertDomainMeta(domain1);
  assertDomainMeta(domain2);

  assert.equal(domain1.domain !== domain2.domain, true);
});

it("should pass on seeded domain generation with sanitization for onion service import", async function () {
  let domain1 = await generateV3OnionDomain("seed one", true);
  let domain2 = await generateV3OnionDomain("seed two", true);
  let domain3 = await generateV3OnionDomain("seed two", true);

  assertDomainMetaServiceSanitized(domain1);
  assertDomainMetaServiceSanitized(domain2);
  assertDomainMetaServiceSanitized(domain3);

  assert.equal(domain1.domain !== domain2.domain, true);
  assert.equal(domain2.domain === domain3.domain, true);
});
