# Contract Testing in SAML Shield

This document explains the contract testing pattern used in SAML Shield

## Overview

Contract testing provides comprehensive, data-driven test coverage by using JSON test case definitions that specify inputs, expected outputs, and test metadata. This approach allows for:

- **Systematic testing** of various SAML scenarios and edge cases
- **Easy addition** of new test cases without code changes
- **Clear separation** between test data and test execution logic
- **Reproducible results** with embedded test data

## Test Structure

### Test Case Format

Each test case is defined in a `.test.json` file with the following structure:

```json
{
  "name": "Descriptive test name",
  "description": "Detailed description of what this test validates",
  "input": {
    "response_xml": "!embed:base64:file://saml_response.xml"
  },
  "shouldSucceed": true,
  "expectedError": "Expected error message (for failing tests)",
  "expectedErrorCode": "EXPECTED_ERROR_CODE",
  "only": false,
  "skip": false
}
```

### Field Descriptions

- `name`: Human-readable test name (optional, defaults to file path)
- `description`: Detailed description of the test case
- `input`: Input parameters passed to the linting function
- `shouldSucceed`: Whether the test should pass (true) or fail (false)
- `expectedError`: Substring that should appear in error message (for failing tests)
- `expectedErrorCode`: Expected error code for failing tests
- `only`: Run only this test (for debugging)
- `skip`: Skip this test

### Embed Directives

Test cases support special directives for embedding external content:

- `!embed:file://path.xml` - Embed file contents as string
- `!embed:base64:file://path.xml` - Embed file contents as base64
- `!embed:base64:string_content` - Encode inline string as base64

Example:

```json
{
  "input": {
    "response_xml": "!embed:base64:file://valid_saml_response.xml"
  }
}
```

## Directory Structure

```
test/contract/
├── data/
│   ├── valid/
│   │   ├── valid_saml_response.test.json
│   │   └── sp_initiated.xml
│   ├── error_cases/
│   │   ├── empty_response.test.json
│   │   ├── invalid_xml.test.json
│   │   ├── missing_signature.test.json
│   │   └── missing_signature.xml
│   └── vulnerabilities/
│       ├── xml_comment_injection.test.json
│       ├── xml_comment_injection.xml
│       ├── multiple_signedinfo.test.json
│       └── multiple_signedinfo.xml
├── loader.ts
└── runner.test.ts
```

## Test Categories

### Valid Cases

Test cases that should pass validation:

- Properly signed SAML responses
- Responses with correct structure
- Responses without security vulnerabilities

### Error Cases

Test cases that should fail due to structural issues:

- Empty or missing response data
- Invalid XML structure
- Missing required signatures
- Malformed SAML responses

### Vulnerabilities

Test cases that should fail due to security vulnerabilities:

- XML comment injection (CVE-2017-11428 family)
- Multiple SignedInfo elements
- Processing instruction injection
- External entity references

## Running Contract Tests

```bash
# Run all tests
yarn test
```

## Adding New Test Cases

1. **Create test data**: Add XML files to the appropriate subdirectory
2. **Create test definition**: Add a `.test.json` file with test metadata
3. **Run tests**: Use `yarn test` to validate

Example new test case:

```json
{
  "name": "New Security Vulnerability",
  "description": "Should detect and block responses with XXE attacks",
  "input": {
    "response_xml": "!embed:base64:file://xxe_attack.xml"
  },
  "shouldSucceed": false,
  "expectedError": "External Entities are forbidden",
  "expectedErrorCode": "XML_VALIDATION_ERROR"
}
```

## Benefits

1. **Comprehensive Coverage**: Easy to add test cases for new vulnerabilities and edge cases
2. **Maintainability**: Test logic is separated from test data
3. **Documentation**: Test cases serve as documentation of expected behavior
4. **Regression Prevention**: Ensures new changes don't break existing security protections
5. **Real-world Data**: Uses actual SAML responses from various identity providers

## Security Focus

The contract tests particularly focus on:

- **XML parsing vulnerabilities** (XXE, billion laughs, quadratic blowup)
- **Signature validation bypasses** (comment injection, multiple SignedInfo)
- **Canonicalization attacks** (processing instructions - always blocked)
- **Structural validation** (missing elements, invalid formats)

This comprehensive testing approach ensures that SAML Shield maintains the same security-first approach as the original Stytch implementation.
