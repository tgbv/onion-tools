# Tor onion domain tools

A set of tools dedicated to onion domains manipulation. Readme file is a pure overview, each exported method is documented better within its comments.

- Requires Node >= 16.
- Requires NPM >= 8.
- Supports only onion V3 domains.

Get it via NPM:

```
npm i onion-tools
```

### 1. Domain generation

You can generate random domains, or deterministically from a predefined seed.

```js
// Generate random domain.
const randomDomainObj = await generateV3OnionDomain()

// Generate domain from seed.
const domainFromSeedObj = await generateV3OnionDomain('some seed')

/**
 * outputs: {
 *  expandedPrivateKey: Buffer,
 *  publicKey: Buffer,
 *  domain: string,
 * }
 */
console.log(randomDomainObj)
```

**By default the generated public/private keys pair cannot be imported by Tor onion service hosting.** If you wish that sanitization pass another boolean parameter to the function. After that you will be able to write the keys to files and import them to onion hosting successfully.

```js
// Generate random domain with keys pair sanitized for hosting import.
const { domain, expandedPrivateKey, publicKey } = await generateV3OnionDomain(undefined, true)

writeFileSync('./hs_ed25519_secret_key', expandedPrivateKey)
writeFileSync('./hs_ed25519_public_key', publicKey)
writeFileSync('./hostname', domain)
```

### 2. Domain validity

You can verify if a domain is valid or not based on it's syntax and checksum. Both methods return booleans.

```js
const domain = 'ciadotgov4sjwlzihbbgxnqg3xiyrg7so2r2o3lt5wz5ypk4sxyjstad.onion'

// Verify domain syntax.
isValidV3OnionDomainSyntax(domain)

// Verify domain syntax + checksum.
isValidV3OnionDomain(domain)
```

### 3. Domain components

You can extract known components of a domain from it, such as public key, checksum and domain version.

```js
const domain = 'ciadotgov4sjwlzihbbgxnqg3xiyrg7so2r2o3lt5wz5ypk4sxyjstad.onion'

const resultObj = extractV3Parts(domain)

/**
 * Outputs: {
 *  publicKey: Buffer,
 *  checksum: Buffer,
 *  version: Buffer,
 * }
 */
console.log(resultObj)
```

### 4. Testing / Contributing

You can test the features of this package by installing its dev dependencies and running the command:

```
npm run test
```

If you wish to contribute, PRs against main branch are welcomed but all previous tests must pass.
