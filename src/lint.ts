import {
  SAMLExpectedAtLeastOneSignatureError,
  SAMLResponseFailureError,
  ValidationError,
  XMLValidationError,
} from "./errors";
import { createSelector, Selector, xmlBase64ToDOM } from "./xml";

export type LintArgs = {
  response_xml: string;
};

export type LintResult = {
  valid: boolean;
  errors?: string[];
};

const SUCCESS_STATUS = "urn:oasis:names:tc:SAML:2.0:status:Success";

function validateSAMLResponseStructure(selector: Selector): void {
  const responseElements = selector.selectElements("//saml2p:Response");
  if (responseElements.length === 0) {
    throw new XMLValidationError(
      "document does not contain a SAML Response element",
    );
  }
  if (responseElements.length > 1) {
    throw new XMLValidationError(
      "document contains multiple SAML Response elements",
    );
  }
}

/**
 * Lints a SAML response for security vulnerabilities and structural validity
 *
 * @param options - Configuration options for linting
 * @returns Promise that resolves when linting is complete
 * @throws Various error types for different validation failures
 */
export async function lintSAMLResponse({
  response_xml,
}: LintArgs): Promise<void> {
  if (!response_xml) {
    throw new ValidationError("missing required field: SAMLResponse");
  }

  const dom = xmlBase64ToDOM(response_xml);
  const selector = createSelector(dom);

  // Validate that this looks like a SAML response first
  validateSAMLResponseStructure(selector);

  const response_id = selector.selectSingleAttribute(
    "//saml2p:Response/@ID",
  ).value;

  // We need to validate the response status before looking for assertions
  // because depending on the failure, there might not be an assertion!
  validateResponseStatus(selector);

  const assertion_id = selector.selectSingleAttribute(
    "//saml:Assertion/@ID",
  ).value;

  const isResponseSigned = !!selector.selectOptionalSingleElement(
    xpathForSignature(response_id),
  );
  const isAssertionSigned = !!selector.selectOptionalSingleElement(
    xpathForSignature(assertion_id),
  );

  if (!isResponseSigned && !isAssertionSigned) {
    throw new SAMLExpectedAtLeastOneSignatureError();
  }

  // We are preemptively blocking all login requests containing comments
  const comments = selector.selectComments("//comment()");
  if (comments.length > 0) {
    const commentDetails = comments.map((c) => ({
      comment: c.nodeValue,
      location: c.parentNode?.nodeName || "root",
    }));
    throw new XMLValidationError("response contained illegal XML comments", {
      comments: commentDetails,
    });
  }

  // We are preemptively blocking all login requests containing multiple SignedInfo Nodes within a single Signature node
  const multipleSignatures = selector.selectElements(
    "//*[local-name()='Signature' and count(*[local-name()='SignedInfo']) > 1]",
  );
  if (multipleSignatures.length > 0) {
    throw new XMLValidationError(
      "response contained multiple SignedInfo elements in a single signature",
    );
  }

  // We are preemptively blocking all login requests containing processing instructions
  const processingInstructions = selector.selectProcessingInstructions(
    "//processing-instruction()",
  );
  if (processingInstructions.length > 0) {
    const processingInstructionsDetails = processingInstructions
      .filter((c) => c.parentNode && c.parentNode?.nodeName !== "#document")
      .map((c) => ({
        processingInstruction: c.nodeValue,
        location: c.parentNode?.nodeName || "root",
      }));
    if (processingInstructionsDetails.length > 0) {
      throw new XMLValidationError(
        "response contained illegal processing instructions",
        {
          comments: processingInstructionsDetails,
        },
      );
    }
  }
}

/**
 * Validate the status of the response -
 *   <StatusCode> is a recursive element that may indicate success or failure
 *   anything other than a value of "urn:oasis:names:tc:SAML:2.0:status:Success" indicates failure
 *   "urn...Requester" means the requester did something invalid
 *   "urn...Responder" means the responder was not able to satisfy the request
 *   "urn...VersionMismatch" means, well, version mismatch
 */
function validateResponseStatus(selector: Selector) {
  const status = selector.selectSingleAttribute(
    "//saml2p:Response/samlp:Status/samlp:StatusCode/@Value",
  ).value;

  if (status === SUCCESS_STATUS) {
    return;
  }

  const failures = selector
    .selectAttributes(
      "//saml2p:Response/samlp:Status/samlp:StatusCode/samlp:StatusCode/@Value",
    )
    .map((failure) => failure.value);

  const response_id =
    selector.selectOptionalSingleAttribute("//saml2p:Response/@ID")?.value ??
    null;

  throw new SAMLResponseFailureError(response_id, status, failures);
}

// Creates an xpath that looks for a <Signature> containing a <Reference> that points to the ID passed in.
const xpathForSignature = (nodeID: string) => {
  return (
    ".//*[" +
    "local-name(.)='Signature' and " +
    "namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#' and " +
    "descendant::*[local-name(.)='Reference' and @URI='#" +
    nodeID +
    "']" +
    "]"
  );
};

/**
 * A safer wrapper around lintSAMLResponse that returns a result object instead of throwing
 *
 * @param options - Configuration options for linting
 * @returns LintResult object indicating success/failure and any issues found
 */
export async function safeLintSAMLResponse(
  options: LintArgs,
): Promise<LintResult> {
  try {
    await lintSAMLResponse(options);
    return {
      valid: true,
    };
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : "Unknown error occurred";
    return {
      valid: false,
      errors: [errorMessage],
    };
  }
}
