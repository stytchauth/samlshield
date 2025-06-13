/**
 * @stytch/samlshield - A Node.js library for linting and validating SAML responses
 *
 * Security-first design to protect against common SAML vulnerabilities including:
 * - XML External Entity (XXE) attacks
 * - XML comment injection vulnerabilities
 * - Multiple SignedInfo element attacks
 * - Processing instruction injection
 * - Signature validation bypass
 */

// Main linting functions
export {
  lintSAMLResponse,
  safeLintSAMLResponse,
  LintArgs,
  LintResult,
} from "./lint";

// XML utilities
export {
  Selector,
  createSelector,
  xmlStringToDOM,
  xmlBase64ToDOM,
} from "./xml";

// Error classes
export {
  SAMLShieldError,
  ValidationError,
  XMLValidationError,
  XPathError,
  XMLExpectedSingletonError,
  XMLExpectedOptionalSingletonError,
  SAMLExpectedAtLeastOneSignatureError,
  XMLExternalEntitiesForbiddenError,
  SAMLResponseFailureError,
  ErrorDetails,
} from "./errors";
