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
    super(`Invalid input: ${reason}`, "VALIDATION_ERROR");
  }
}

export class XMLValidationError extends SAMLShieldError {
  constructor(reason: string, details?: ErrorDetails) {
    super(`Invalid input: ${reason}`, "XML_VALIDATION_ERROR", {
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
      "SAML_ASSERTION_NOT_SIGNED",
    );
  }
}

export class XMLExternalEntitiesForbiddenError extends SAMLShieldError {
  constructor() {
    super(
      "Invalid input: External Entities are forbidden",
      "XML_VALIDATION_ERROR",
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
      "SAML_LOGIN_FAILED",
      {
        response_id,
        saml_status_code,
        nested_status_codes,
      },
    );
  }
}
