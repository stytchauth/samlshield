# Security Validations - Malicious Test Cases

This directory contains contract tests for malicious SAML payloads that should be blocked by specific security validation functions in the SAMLShield library.

## Test Coverage

### performStringLevelValidation

- `doctype_simple_attack` - Tests blocking of DOCTYPE declarations without entities at string level

### validateElementCounts

- `multiple_assertions_attack` - Tests blocking of multiple assertion elements
- `forbidden_authnrequest_attack` - Tests blocking of forbidden AuthnRequest elements

### validateSAMLResponseStructure

- `multiple_responses_attack` - Tests blocking of multiple response elements

### validateSignatureURI

- `malformed_uri_working_base` - Tests blocking of malformed URI references
- `nonexistent_id_working_base` - Tests blocking of URI references to nonexistent IDs

### validateCanonicalizationMethod

- `invalid_canonicalization_attack` - Tests blocking of invalid canonicalization algorithms

### validateTransforms

- `too_many_transforms_attack` - Tests blocking of excessive transform elements (>2)
- `invalid_transform_attack` - Tests blocking of invalid transform algorithms

### XML Parser Validation (not performStringLevelValidation)

- `doctype_entity_attack` - Tests that DOCTYPE with entities is caught by XML parser

## Purpose

These tests ensure that the security validation functions correctly identify and block various types of SAML-based attacks and malicious payloads while maintaining backward compatibility with legitimate SAML responses.
