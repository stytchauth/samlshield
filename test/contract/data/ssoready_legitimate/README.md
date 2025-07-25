# SSO Ready Legitimate Test Cases

This directory contains contract tests for legitimate SAML payloads that should pass validation, inspired by test data patterns from the ssoready/ssoready repository.

## Source Attribution

Test data patterns are inspired by the ssoready/ssoready repository:

- Repository: https://github.com/ssoready/ssoready
- License: MIT
- Location: internal/saml/testdata/assertions

The actual test data in this directory has been created to follow similar patterns while being original content that tests the SAMLShield validation functions.

## Test Coverage

### Legitimate SAML Responses

- `ssoready_example_response` - Valid SAML response with proper structure, signatures, and assertions
- `valid_response_with_signatures` - Valid SAML response with both response and assertion signatures

## Purpose

These tests ensure that legitimate SAML responses from various identity providers will pass through all security validations without being incorrectly blocked. This maintains backward compatibility while the security enhancements protect against malicious payloads.

## Adding More Test Cases

When adding new legitimate test cases:

1. Ensure they represent real-world SAML response patterns
2. Verify they pass all current security validations
3. Include proper attribution if inspired by external sources
4. Document any specific identity provider patterns being tested
