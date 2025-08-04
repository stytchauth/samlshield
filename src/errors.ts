/**
 * Custom error classes for SAML validation and processing
 */

export type ErrorDetails = Record<string, unknown>;

export class SAMLShieldError extends Error {
  public code: string;
  public details?: ErrorDetails;

  constructor(message: string, code: string, details?: ErrorDetails) {
    super(message);
    this.code = code;
    this.details = details;
  }
}

export class ValidationError extends SAMLShieldError {
  constructor(reason: string) {
    super(`Invalid input: ${reason}`, "validation_error");
  }
}

export class XMLValidationError extends SAMLShieldError {
  constructor(reason: string, details?: ErrorDetails) {
    super(`Invalid input: ${reason}`, "xml_validation_error", {
      ...details,
      invalid_input: reason,
    });
  }
}

export class XPathError extends XMLValidationError {
  constructor(xpath: string, expected: string, received: string) {
    super(`expected a ${expected} at path "${xpath}" but received ${received}`);
  }
}

export class XMLExpectedSingletonError extends XMLValidationError {
  constructor(xpath: string, expected: string, count: number) {
    super(
      `expected exactly one ${expected} at path "${xpath}" but received ${count}`,
    );
  }
}

export class XMLExpectedOptionalSingletonError extends XMLValidationError {
  constructor(xpath: string, expected: string, count: number) {
    super(
      `expected at most one ${expected} at path "${xpath}" but received ${count}`,
    );
  }
}

export class SAMLExpectedAtLeastOneSignatureError extends SAMLShieldError {
  constructor() {
    super(
      "Invalid input: one of response or assertion must be signed",
      "saml_assertion_not_signed",
    );
  }
}

export class XMLExternalEntitiesForbiddenError extends SAMLShieldError {
  constructor() {
    super(
      "Invalid input: External Entities are forbidden",
      "xml_validation_error",
      { invalid_input: "External Entities are forbidden" },
    );
  }
}

export class SAMLResponseFailureError extends SAMLShieldError {
  constructor(
    response_id: unknown,
    saml_status_code: unknown,
    nested_status_codes: unknown[],
  ) {
    super(
      "IDP was not able to complete the login as requested",
      "saml_login_failed",
      {
        response_id,
        saml_status_code,
        nested_status_codes,
      },
    );
  }
}

export class SAMLAssertionExpiredError extends SAMLShieldError {
  constructor() {
    super(
      "SAML assertion expired: clocks skewed too much",
      "saml_assertion_expired",
    );
  }
}

export class SAMLAssertionNotYetValidError extends SAMLShieldError {
  constructor() {
    super("SAML assertion not yet valid", "saml_assertion_not_yet_valid");
  }
}
