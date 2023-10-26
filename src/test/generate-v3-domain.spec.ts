import { IV3DomainBones, generateV3OnionDomain, isValidV3OnionDomain } from "../index";

/**
 * Helper function for asserting domain meta.
 */
function assertDomainBones(domainMeta: IV3DomainBones) {
  expect(domainMeta.publicKey).toHaveLength(32);
  expect(domainMeta.expandedPrivateKey).toHaveLength(64);

  expect(isValidV3OnionDomain(domainMeta.domain)).toBe(true);
}

/**
 * Helper function for asserting domain meta.
 */
function assertDomainBonesServiceSanitized(domainMeta: IV3DomainBones) {
  expect(domainMeta.publicKey).toHaveLength(64);
  expect(domainMeta.expandedPrivateKey).toHaveLength(96);

  expect(isValidV3OnionDomain(domainMeta.domain)).toBe(true);
}

it("should pass on random domain generation", async function () {
  let result = await generateV3OnionDomain();

  assertDomainBones(result);
});

it("should pass on random domain generation with sanitization for onion service import", async function () {
  let result = await generateV3OnionDomain(undefined, true);

  assertDomainBonesServiceSanitized(result);
});

it("should pass on seeded domain generation", async function () {
  let domain1 = await generateV3OnionDomain("seed one");
  let domain2 = await generateV3OnionDomain("seed two");
  let domain3 = await generateV3OnionDomain("seed two");

  assertDomainBones(domain1);
  assertDomainBones(domain2);

  expect(domain1.domain).not.toBe(domain2.domain);
  expect(domain2.domain).toBe(domain3.domain);
});

it("should pass on seeded domain generation with sanitization for onion service import", async function () {
  let domain1 = await generateV3OnionDomain("seed one", true);
  let domain2 = await generateV3OnionDomain("seed two", true);
  let domain3 = await generateV3OnionDomain("seed two", true);

  assertDomainBonesServiceSanitized(domain1);
  assertDomainBonesServiceSanitized(domain2);
  assertDomainBonesServiceSanitized(domain3);

  expect(domain1.domain).not.toBe(domain2.domain);
  expect(domain2.domain).toBe(domain3.domain);
});
