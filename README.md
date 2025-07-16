# samlshield

A Node.js library for linting and validating SAML responses. This library provides security-first SAML validation to protect against common vulnerabilities.

## Features

- **XML External Entity (XXE) Attack Protection**: Prevents malicious external entity references
- **XML Comment Injection Detection**: Identifies and blocks responses with embedded XML comments
- **Multiple SignedInfo Element Detection**: Catches signature manipulation attempts
- **Processing Instruction Validation**: Detects potentially malicious processing instructions
- **Signature Validation**: Ensures either the response or assertion is properly signed
- **Structural Validation**: Verifies proper SAML response structure

## Installation

```bash
yarn add @stytch/samlshield
```

## Development Setup

For contributing to this project:

```bash
yarn install
yarn hooks # registers Git hooks locally
```

## Quick Start

```javascript
import { lintSAMLResponse, safeLintSAMLResponse } from "@stytch/samlshield";

// Basic usage - throws errors on validation failure
try {
  await lintSAMLResponse({
    response_xml: "base64-encoded-saml-response",
  });
  console.log("SAML response is valid!");
} catch (error) {
  console.error("SAML validation failed:", error.message);
}

// Safe usage - returns result object instead of throwing
const result = await safeLintSAMLResponse({
  response_xml: "base64-encoded-saml-response",
});

if (result.valid) {
  console.log("SAML response is valid!");
} else {
  console.error("Validation errors:", result.errors);
}
```

## API Reference

### `lintSAMLResponse(options: LintArgs): Promise<void>`

Main linting function that validates a SAML response for security vulnerabilities.

**Parameters:**

- `options.response_xml` (string): Base64-encoded SAML response XML

**Throws:**

- `ValidationError`: For basic input validation failures
- `XMLValidationError`: For XML parsing and structure issues
- `SAMLExpectedAtLeastOneSignatureError`: When neither response nor assertion is signed
- `SAMLResponseFailureError`: When the SAML response indicates authentication failure

### `safeLintSAMLResponse(options: LintArgs): Promise<LintResult>`

Wrapper around `lintSAMLResponse` that returns a result object instead of throwing.

**Returns:**

```typescript
{
  valid: boolean;
  errors?: string[];
}
```

### Error Classes

All error classes extend `SAMLShieldError` with additional context:

- `ValidationError`: Basic input validation failures
- `XMLValidationError`: XML parsing and structure issues
- `SAMLExpectedAtLeastOneSignatureError`: Missing required signatures
- `XMLExternalEntitiesForbiddenError`: External entity reference attempts
- `SAMLResponseFailureError`: SAML authentication failures

## Security Features

This library implements multiple layers of security validation:

### 1. XML External Entity (XXE) Protection

Prevents attackers from including external entities that could expose sensitive files or cause denial of service.

### 2. XML Comment Injection Prevention

Blocks SAML responses containing XML comments, which can be used to bypass signature validation (CVE-2017-11428 family).

### 3. Multiple SignedInfo Detection

Identifies responses with multiple SignedInfo elements within a single signature, which can be used for signature wrapping attacks.

### 4. Processing Instruction Validation

Always detects and blocks processing instructions that could be used for XML canonicalization attacks.

### 5. Signature Requirements

Ensures that either the SAML response or the assertion within it is digitally signed.

## Low-Level XML Utilities

The library also exports low-level XML utilities for advanced use cases:

```javascript
import {
  createSelector,
  xmlStringToDOM,
  xmlBase64ToDOM,
} from "@stytch/samlshield";

// Parse XML from string
const dom = xmlStringToDOM("<saml:Response>...</saml:Response>");

// Parse XML from base64
const dom2 = xmlBase64ToDOM("base64-encoded-xml");

// Create XPath selector with SAML namespaces
const selector = createSelector(dom);
const elements = selector.selectElements("//saml2p:Response");
```

## Testing

SAML Shield includes comprehensive test coverage:

```bash
# Run all tests
yarn test
```

The library uses a **contract testing pattern**, providing systematic testing of:

- Valid SAML responses from major identity providers
- Security vulnerability detection (XXE, comment injection, etc.)
- Edge cases and error conditions

See [CONTRACT_TESTING.md](CONTRACT_TESTING.md) for details on the testing approach.

## Development Workflow

### Preparing to push

- `yarn format` - formats TypeScript code
- `yarn lint` - runs linter
- `yarn build` - builds and checks types
- `yarn test` - runs test suite

We use [`husky`](https://github.com/typicode/husky) to run these all in a pre-commit hook.

## Based on Stytch's Auth API

This library is based on the battle-tested SAML validation logic from [Stytch's](https://stytch.com) production Auth API service, which processes millions of SAML authentications. The original implementation has been adapted for standalone use while maintaining the same security-first approach.

## License

Apache-2.0
