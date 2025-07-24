import {
  SAMLExpectedAtLeastOneSignatureError,
  SAMLResponseFailureError,
  ValidationError,
  XMLValidationError,
} from "./errors";
import { createSelector, Selector, xmlBase64ToDOM } from "./xml";

export type ValidateArgs = {
  response_xml: string;
};

export type ValidateResult = {
  valid: boolean;
  errors?: string[];
};

const SUCCESS_STATUS = "urn:oasis:names:tc:SAML:2.0:status:Success";

/**
 * Perform string-level validation before XML parsing
 * This catches DOCTYPE and other string-level security issues
 */
function performStringLevelValidation(xmlString: string): void {
  // Decode base64 to get the actual XML string
  const decoded = Buffer.from(xmlString, "base64").toString();

  // Block DOCTYPE at string level, but allow entity-related DOCTYPEs to be handled by XML parser
  // for more specific error messages about external entities
  if (decoded.includes("<!DOCTYPE") && !decoded.includes("<!ENTITY")) {
    throw new XMLValidationError("DOCTYPE detected and blocked");
  }
}

/**
 * Validate the document structure and node types
 * Only allow element and text nodes, block exotic node types
 */
function validateDocumentStructure(dom: Node): void {
  // Check for DTD in parsed document
  const document = dom.ownerDocument || (dom as Document);
  if (document.doctype) {
    throw new XMLValidationError("Payload contains doctype");
  }

  // Note: We don't traverse nodes here to block comments/processing instructions
  // because the main validation function handles those with specific error messages
  // This is reserved for other exotic node types that shouldn't exist
}

/**
 * Validate element counts to prevent structure manipulation attacks
 */
function validateElementCounts(selector: Selector): void {
  // Ensure exactly one Response element
  const responseElements = selector.selectElements("//saml2p:Response");
  if (responseElements.length !== 1) {
    throw new XMLValidationError(
      `Found ${responseElements.length} Response elements. Only one allowed`,
    );
  }

  // Ensure exactly one Assertion or EncryptedAssertion (but not both)
  const assertions = selector.selectElements("//*[local-name()='Assertion']");
  const encryptedAssertions = selector.selectElements(
    "//*[local-name()='EncryptedAssertion']",
  );
  const totalAssertions = assertions.length + encryptedAssertions.length;

  if (totalAssertions !== 1) {
    throw new XMLValidationError(
      `Found ${totalAssertions} of Assertions/EncryptedAssertion elements. Only one allowed`,
    );
  }

  // Block forbidden elements that shouldn't appear in responses
  const forbiddenElements = [
    "EntityDescriptor",
    "AuthnRequest",
    "LogoutRequest",
    "AssertionIDRequest",
    "SubjectQuery",
    "ManageNameIDRequest",
    "ManageNameIDResponse",
    "LogoutResponse",
    "NameIDMappingResponseType",
  ];

  forbiddenElements.forEach((elementName) => {
    const elements = selector.selectElements(
      `//*[local-name()='${elementName}']`,
    );
    if (elements.length > 0) {
      throw new XMLValidationError(
        `Found ${elements.length} ${elementName} elements. None allowed in SAML responses`,
      );
    }
  });
}

/**
 * Validate assertion location to prevent assertion confusion attacks
 */
function validateAssertionLocation(selector: Selector): void {
  const assertions = selector.selectElements("//*[local-name()='Assertion']");

  if (assertions.length > 0) {
    // Find the assertion and verify it's in the expected location
    const foundAssertion = assertions[0];
    try {
      const expectedAssertion = selector.selectOptionalSingleElement(
        "//saml2p:Response/saml:Assertion",
      );

      if (!expectedAssertion || foundAssertion !== expectedAssertion) {
        throw new XMLValidationError(
          "Unexpected assertion location - assertion confusion attack detected",
        );
      }
    } catch (error) {
      // If we can't find the assertion in the expected location, that's suspicious
      throw new XMLValidationError(
        "Unexpected assertion location - assertion confusion attack detected",
      );
    }
  }
}

/**
 * Enhanced signature profile validation based on Ruby Firewall
 * Validates signature structure, canonicalization methods, and transforms
 */
function validateSignatureProfiles(selector: Selector): void {
  const signatures = selector.selectElements("//*[local-name()='Signature']");

  signatures.forEach((signature) => {
    validateIndividualSignature(signature, selector);
  });
}

/**
 * Validate individual signature structure and profile
 */
function validateIndividualSignature(
  signature: Element,
  selector: Selector,
): void {
  // Check if this signature element is actually present in the document
  const signatureXPath = `//*[local-name()='Signature']`;
  const allSignatures = selector.selectElements(signatureXPath);

  // Find the signature that corresponds to our element
  let currentSignatureIndex = -1;
  for (let i = 0; i < allSignatures.length; i++) {
    if (allSignatures[i] === signature) {
      currentSignatureIndex = i;
      break;
    }
  }

  if (currentSignatureIndex === -1) {
    throw new XMLValidationError("Signature element not found in document");
  }

  // Use XPath to find SignedInfo elements within this specific signature
  const signedInfoXPath = `(//ds:Signature)[${currentSignatureIndex + 1}]/ds:SignedInfo`;
  const signedInfoNodes = selector.selectElements(signedInfoXPath);

  if (signedInfoNodes.length !== 1) {
    throw new XMLValidationError(
      `Expected exactly one SignedInfo element, found ${signedInfoNodes.length}`,
    );
  }

  // Use XPath to find Reference elements within the SignedInfo
  const referenceXPath = `(//ds:Signature)[${currentSignatureIndex + 1}]/ds:SignedInfo/ds:Reference`;
  const referenceNodes = selector.selectElements(referenceXPath);

  if (referenceNodes.length !== 1) {
    throw new XMLValidationError(
      `Expected exactly one Reference element, found ${referenceNodes.length}`,
    );
  }

  // Validate URI attribute
  validateSignatureURI(referenceNodes[0], selector, currentSignatureIndex);

  // Validate canonicalization method
  validateCanonicalizationMethod(selector, currentSignatureIndex);

  // Validate transforms
  validateTransforms(selector, currentSignatureIndex);
}

/**
 * Validate signature URI references
 */
function validateSignatureURI(
  reference: Element,
  selector: Selector,
  signatureIndex: number,
): void {
  const uriAttr = selector.selectOptionalSingleAttribute(
    `(//ds:Signature)[${signatureIndex + 1}]/ds:SignedInfo/ds:Reference/@URI`,
  );

  if (!uriAttr) {
    throw new XMLValidationError("Signature Reference missing URI attribute");
  }

  const uri = uriAttr.value;

  // URI should either be empty (root document) or reference an ID with #
  if (uri === "") {
    // Empty URI should reference root document
    return;
  }

  if (!uri.startsWith("#")) {
    throw new XMLValidationError(`Malformed URI: ${uri}`);
  }

  // Validate that the referenced ID exists and is unique
  const referencedId = uri.substring(1);
  const referencedElements = selector.selectElements(
    `//*[@ID='${referencedId}']`,
  );

  if (referencedElements.length === 0) {
    throw new XMLValidationError(
      `URI references non-existent ID: ${referencedId}`,
    );
  }

  if (referencedElements.length > 1) {
    throw new XMLValidationError(
      `Ambiguous reference URI: ${referencedId}, references ${referencedElements.length} elements`,
    );
  }
}

/**
 * Validate canonicalization method
 */
function validateCanonicalizationMethod(
  selector: Selector,
  signatureIndex: number,
): void {
  const c14nMethods = selector.selectElements(
    `(//ds:Signature)[${signatureIndex + 1}]/ds:SignedInfo/ds:CanonicalizationMethod`,
  );

  if (c14nMethods.length !== 1) {
    throw new XMLValidationError(
      `Expected exactly one CanonicalizationMethod, found ${c14nMethods.length}`,
    );
  }

  const algorithmAttr = selector.selectOptionalSingleAttribute(
    `(//ds:Signature)[${signatureIndex + 1}]/ds:SignedInfo/ds:CanonicalizationMethod/@Algorithm`,
  );

  const algorithm = algorithmAttr?.value;

  const allowedAlgorithms = [
    "http://www.w3.org/2001/10/xml-exc-c14n#",
    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
  ];

  if (!algorithm || !allowedAlgorithms.includes(algorithm)) {
    throw new XMLValidationError(
      `Invalid CanonicalizationMethod algorithm: ${algorithm}`,
    );
  }
}

/**
 * Validate signature transforms
 */
function validateTransforms(selector: Selector, signatureIndex: number): void {
  const transforms = selector.selectElements(
    `(//ds:Signature)[${signatureIndex + 1}]/ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform`,
  );

  if (transforms.length > 2) {
    throw new XMLValidationError(
      `Too many transforms: ${transforms.length}. Maximum 2 allowed`,
    );
  }

  const allowedTransforms = [
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
    "http://www.w3.org/2001/10/xml-exc-c14n#",
    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
  ];

  transforms.forEach((transform, index) => {
    const algorithmAttr = selector.selectOptionalSingleAttribute(
      `(//ds:Signature)[${signatureIndex + 1}]/ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform[${index + 1}]/@Algorithm`,
    );

    const algorithm = algorithmAttr?.value;
    if (!algorithm || !allowedTransforms.includes(algorithm)) {
      throw new XMLValidationError(
        `Unexpected transform algorithm: ${algorithm}`,
      );
    }
  });
}

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
 * Validates a SAML response for security vulnerabilities and structural validity
 *
 * @param options - Configuration options for validation
 * @returns Promise that resolves when validation is complete
 * @throws Various error types for different validation failures
 */
export async function validateSAMLResponse({
  response_xml,
}: ValidateArgs): Promise<void> {
  if (!response_xml) {
    throw new ValidationError("missing required field: SAMLResponse");
  }

  // First, perform string-level validation before XML parsing
  performStringLevelValidation(response_xml);

  const dom = xmlBase64ToDOM(response_xml);
  const selector = createSelector(dom);

  // Validate that this looks like a SAML response first
  validateSAMLResponseStructure(selector);

  // Validate document structure and node types
  validateDocumentStructure(dom);

  // Validate element counts to prevent structure manipulation
  validateElementCounts(selector);

  // Validate assertion location to prevent confusion attacks
  validateAssertionLocation(selector);

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

  // Enhanced signature profile validation (after existing validations pass)
  validateSignatureProfiles(selector);

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
 * A safer wrapper around validateSAMLResponse that returns a result object instead of throwing
 *
 * @param options - Configuration options for validation
 * @returns ValidateResult object indicating success/failure and any issues found
 */
export async function safeValidateSAMLResponse(
  options: ValidateArgs,
): Promise<ValidateResult> {
  try {
    await validateSAMLResponse(options);
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
