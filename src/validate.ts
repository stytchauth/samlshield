import {
  SAMLAssertionExpiredError,
  SAMLAssertionNotYetValidError,
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

export type ParsedSAMLResponse = {
  responseElement: Element;
  assertionElement: Element | null;
  encryptedAssertionElement: Element | null;
  responseId: string;
  assertionId: string | null;
  isResponseSigned: boolean;
  isAssertionSigned: boolean;
  signedResponseElement: Element | null;
  signedAssertionElement: Element | null;
};

const SUCCESS_STATUS = "urn:oasis:names:tc:SAML:2.0:status:Success";

/**
 * Escape XPath attribute values to prevent injection
 */
function escapeXPathAttribute(value: string): string {
  // If the value contains single quotes, we need to use concat() or double quotes
  if (value.includes("'")) {
    if (value.includes('"')) {
      // Value contains both single and double quotes, use concat()
      const parts = value.split("'");
      return `concat('${parts.join("', \"'\", '")}')`;
    } else {
      // Value contains single quotes but not double quotes
      return `"${value}"`;
    }
  } else {
    // Value doesn't contain single quotes
    return `'${value}'`;
  }
}

/**
 * Validate that a string is a safe XML identifier (for ID attributes)
 */
function validateXMLIdentifier(id: string): void {
  if (!id || typeof id !== "string") {
    throw new XMLValidationError(
      "Invalid XML identifier: must be non-empty string",
    );
  }

  // XML Name production: must start with letter/underscore, followed by name characters
  // We'll be strict and only allow alphanumeric + underscore/hyphen for safety
  if (!/^[a-zA-Z0-9_-]*$/.test(id)) {
    throw new XMLValidationError(
      `Invalid XML identifier: ${id}. Must start with letter/underscore and contain only alphanumeric characters, underscores, and hyphens`,
    );
  }
}

/**
 * Perform string-level validation before XML parsing
 * Block all DOCTYPE declarations outright
 */
function performStringLevelValidation(xmlString: string): void {
  // Decode base64 to get the actual XML string
  const decoded = Buffer.from(xmlString, "base64").toString();

  // Check for entity attacks first (more specific)
  if (decoded.includes("<!ENTITY")) {
    throw new XMLValidationError("External Entities are forbidden");
  }

  // Block all other DOCTYPE declarations
  if (decoded.includes("<!DOCTYPE")) {
    throw new XMLValidationError("DOCTYPE detected and blocked");
  }
}

/**
 * Manually traverse all nodes to block forbidden node types
 * This is done as the first step after parsing for security
 */
function blockForbiddenNodes(node: Node): void {
  // Block DOCTYPE nodes at document level
  const document = node.ownerDocument || (node as Document);
  if (document.doctype) {
    throw new XMLValidationError("Payload contains doctype");
  }

  // Recursively traverse all nodes
  function traverseNode(currentNode: Node): void {
    // Block forbidden node types
    switch (currentNode.nodeType) {
      case currentNode.COMMENT_NODE:
        throw new XMLValidationError(
          "response contained illegal XML comments",
          {
            comment: currentNode.nodeValue,
            location: currentNode.parentNode?.nodeName || "unknown",
          },
        );

      case currentNode.PROCESSING_INSTRUCTION_NODE:
        // Allow processing instructions only at document level (like XML declaration)
        if (
          currentNode.parentNode &&
          currentNode.parentNode.nodeType !== currentNode.DOCUMENT_NODE
        ) {
          throw new XMLValidationError(
            "response contained illegal processing instructions",
            {
              processingInstruction: currentNode.nodeValue,
              location: currentNode.parentNode?.nodeName || "unknown",
            },
          );
        }
        break;

      case currentNode.DOCUMENT_TYPE_NODE:
        throw new XMLValidationError("Document type nodes are forbidden");

      case currentNode.ENTITY_NODE:
      case currentNode.ENTITY_REFERENCE_NODE:
        throw new XMLValidationError("External Entities are forbidden");

      case currentNode.NOTATION_NODE:
        throw new XMLValidationError("Notation nodes are forbidden");

      // Allow these node types
      case currentNode.ELEMENT_NODE:
      case currentNode.ATTRIBUTE_NODE:
      case currentNode.TEXT_NODE:
      case currentNode.CDATA_SECTION_NODE:
      case currentNode.DOCUMENT_NODE:
      case currentNode.DOCUMENT_FRAGMENT_NODE:
        break;

      default:
        throw new XMLValidationError(
          `Unknown or forbidden node type: ${currentNode.nodeType}`,
        );
    }

    // Recursively check child nodes
    if (currentNode.childNodes) {
      for (let i = 0; i < currentNode.childNodes.length; i++) {
        traverseNode(currentNode.childNodes[i]);
      }
    }
  }

  traverseNode(node);
}

/**
 * Parse and identify the core SAML elements and their signature status
 * Uses strict XPath expressions and validates liberal vs strict results
 */
function parseSAMLResponseStructure(selector: Selector): ParsedSAMLResponse {
  // Find the Response element using strict XPath
  const responseElementsStrict = selector.selectElements("./saml2p:Response");

  // Also check with liberal XPath to ensure they match
  const responseElementsLiberal = selector.selectElements(
    "//*[local-name()='Response']",
  );

  if (responseElementsLiberal.length > 1) {
    throw new XMLValidationError(
      "document contains multiple SAML Response elements",
    );
  }

  if (responseElementsLiberal.length === 0) {
    throw new XMLValidationError(
      "document does not contain a SAML Response element",
    );
  }

  // Validate liberal vs strict matching
  if (responseElementsLiberal.length !== responseElementsStrict.length) {
    throw new XMLValidationError(
      "Response element location mismatch - potential structure manipulation",
    );
  }

  if (responseElementsStrict.length !== 1) {
    if (responseElementsLiberal.length === 0) {
      throw new XMLValidationError(
        "document does not contain a SAML Response element",
      );
    }
    if (responseElementsLiberal.length > 1) {
      throw new XMLValidationError(
        "document contains multiple SAML Response elements",
      );
    }
    throw new XMLValidationError(
      "Response element found but not at expected root location",
    );
  }

  // Verify liberal and strict find the same element
  if (responseElementsLiberal[0] !== responseElementsStrict[0]) {
    throw new XMLValidationError(
      "Response element location mismatch - found Response outside expected location",
    );
  }

  const responseElement = responseElementsStrict[0];
  const responseId = responseElement.getAttribute("ID");
  if (!responseId) {
    throw new XMLValidationError(
      "Response element missing required ID attribute",
    );
  }

  // Validate the ID is safe
  validateXMLIdentifier(responseId);

  // Find assertion or encrypted assertion within the response - assertions should be direct children
  const responseSelector = createSelector(responseElement);
  const assertionsStrict = responseSelector.selectElements("./saml:Assertion");
  const encryptedAssertionsStrict = responseSelector.selectElements(
    "./saml:EncryptedAssertion",
  );

  // Validate with liberal search
  const assertionsLiberal = responseSelector.selectElements(
    ".//*[local-name()='Assertion']",
  );
  const encryptedAssertionsLiberal = responseSelector.selectElements(
    ".//*[local-name()='EncryptedAssertion']",
  );

  // Ensure liberal and strict results match
  if (
    assertionsLiberal.length !== assertionsStrict.length ||
    encryptedAssertionsLiberal.length !== encryptedAssertionsStrict.length
  ) {
    throw new XMLValidationError(
      "Assertion element location mismatch - potential structure manipulation",
    );
  }

  const totalAssertions =
    assertionsStrict.length + encryptedAssertionsStrict.length;
  if (totalAssertions !== 1) {
    throw new XMLValidationError(
      `Found ${totalAssertions} of Assertions/EncryptedAssertion elements. Only one allowed`,
    );
  }

  let assertionElement: Element | null = null;
  let encryptedAssertionElement: Element | null = null;
  let assertionId: string | null = null;

  if (assertionsStrict.length === 1) {
    // Verify liberal and strict find the same element
    if (assertionsLiberal[0] !== assertionsStrict[0]) {
      throw new XMLValidationError(
        "Assertion element location mismatch - assertion confusion attack detected",
      );
    }

    assertionElement = assertionsStrict[0];
    assertionId = assertionElement.getAttribute("ID");
    if (!assertionId) {
      throw new XMLValidationError(
        "Assertion element missing required ID attribute",
      );
    }

    // Validate the ID is safe
    validateXMLIdentifier(assertionId);
  } else {
    // Verify liberal and strict find the same element
    if (encryptedAssertionsLiberal[0] !== encryptedAssertionsStrict[0]) {
      throw new XMLValidationError(
        "EncryptedAssertion element location mismatch - assertion confusion attack detected",
      );
    }

    encryptedAssertionElement = encryptedAssertionsStrict[0];
    // Encrypted assertions don't have IDs we can validate signatures against
  }

  // Check signature status by looking for signatures that reference these elements
  const isResponseSigned = !!selector.selectOptionalSingleElement(
    createSignatureXPath(responseId),
  );

  const isAssertionSigned = assertionId
    ? !!selector.selectOptionalSingleElement(createSignatureXPath(assertionId))
    : false;

  // Find the actual signed elements (the elements that contain the signatures)
  let signedResponseElement: Element | null = null;
  let signedAssertionElement: Element | null = null;

  if (isResponseSigned) {
    signedResponseElement = responseElement;
  }

  if (isAssertionSigned && assertionElement) {
    signedAssertionElement = assertionElement;
  }

  return {
    responseElement,
    assertionElement,
    encryptedAssertionElement,
    responseId,
    assertionId,
    isResponseSigned,
    isAssertionSigned,
    signedResponseElement,
    signedAssertionElement,
  };
}

/**
 * Validate that at least one element is signed and check response status
 * Uses strict XPath and validates against liberal search for consistency
 * Note: Encrypted assertions are accepted unsigned since we cannot validate their content before decryption
 */
function validateCoreRequirements(parsed: ParsedSAMLResponse): void {
  // For encrypted assertions, we allow the case where only the response is signed
  // or neither is signed (since the assertion may be signed within the encrypted content)
  const hasEncryptedAssertion = !!parsed.encryptedAssertionElement;

  if (
    !hasEncryptedAssertion &&
    !parsed.isResponseSigned &&
    !parsed.isAssertionSigned
  ) {
    // If no encrypted assertion, require at least one signature
    throw new SAMLExpectedAtLeastOneSignatureError();
  } else if (hasEncryptedAssertion && !parsed.isResponseSigned) {
    // For encrypted assertions, we still require the response to be signed
    // The assertion signature will be validated after decryption by the consumer
    throw new XMLValidationError(
      "Response must be signed when containing encrypted assertions",
    );
  }

  // Validate response status - Status should be direct child of Response
  const responseSelector = createSelector(parsed.responseElement);
  const statusCodeStrict = responseSelector.selectOptionalSingleAttribute(
    "./samlp:Status/samlp:StatusCode/@Value",
  );

  // Also check with liberal search to ensure consistency
  const statusCodeLiberal = responseSelector.selectOptionalSingleAttribute(
    ".//*[local-name()='StatusCode']/@Value",
  );

  if (!statusCodeStrict) {
    throw new XMLValidationError("Response missing required StatusCode");
  }

  if (
    !statusCodeLiberal ||
    statusCodeStrict.value !== statusCodeLiberal.value
  ) {
    throw new XMLValidationError(
      "StatusCode element location mismatch - potential structure manipulation",
    );
  }

  const status = statusCodeStrict.value;
  if (status !== SUCCESS_STATUS) {
    const failuresStrict = responseSelector
      .selectAttributes(
        "./samlp:Status/samlp:StatusCode/samlp:StatusCode/@Value",
      )
      .map((failure) => failure.value);

    throw new SAMLResponseFailureError(
      parsed.responseId,
      status,
      failuresStrict,
    );
  }
}

/**
 * Validate signature structure and association with parent elements
 * Implements the Ruby logic to ensure each signature is properly associated with Response/Assertion
 */
function validateSignatureProfiles(parsed: ParsedSAMLResponse): void {
  // Find all signatures in the document using liberal search
  const documentSelector = createSelector(
    parsed.responseElement.ownerDocument || parsed.responseElement,
  );
  const allSignatures = documentSelector.selectElements(
    "//*[local-name()='Signature']",
  );

  // Find expected signatures as direct children of Response and Assertion
  const responseSelector = createSelector(parsed.responseElement);
  const expectedResponseSignature =
    responseSelector.selectOptionalSingleElement("./ds:Signature");

  let expectedAssertionSignature: Element | null = null;
  if (parsed.assertionElement) {
    const assertionSelector = createSelector(parsed.assertionElement);
    expectedAssertionSignature =
      assertionSelector.selectOptionalSingleElement("./ds:Signature");
  }

  if (allSignatures.length === 0) {
    // Allow unsigned encrypted assertions - they may be signed within the encrypted content
    if (parsed.encryptedAssertionElement && parsed.isResponseSigned) {
      // Response is signed, encrypted assertion can be unsigned
      return;
    }
    // If no encrypted assertion or response is not signed, this should not happen
    // as validateCoreRequirements should have caught this
    return;
  } else if (allSignatures.length === 1) {
    const foundSignature = allSignatures[0];

    if (foundSignature && foundSignature === expectedResponseSignature) {
      validateIndividualSignatureProfile(
        foundSignature,
        parsed.responseElement,
      );
    } else if (
      foundSignature &&
      foundSignature === expectedAssertionSignature
    ) {
      validateIndividualSignatureProfile(
        foundSignature,
        parsed.assertionElement!,
      );
    } else {
      throw new XMLValidationError(
        "Found signature is not the direct child of either the Response element or the Assertion element",
      );
    }
  } else if (allSignatures.length === 2) {
    if (
      !expectedResponseSignature ||
      allSignatures[0] !== expectedResponseSignature
    ) {
      throw new XMLValidationError(
        "Unexpected Response Signature - first signature must be direct child of Response",
      );
    }
    if (
      !expectedAssertionSignature ||
      allSignatures[1] !== expectedAssertionSignature
    ) {
      throw new XMLValidationError(
        "Unexpected assertion signature - second signature must be direct child of Assertion",
      );
    }

    validateIndividualSignatureProfile(
      allSignatures[0],
      parsed.responseElement,
    );
    validateIndividualSignatureProfile(
      allSignatures[1],
      parsed.assertionElement!,
    );
  } else {
    throw new XMLValidationError(
      `Unexpected number of signatures: ${allSignatures.length}. Expected 0, 1, or 2.`,
    );
  }
}

/**
 * Validate individual signature profile within its parent element
 * Uses strict "parse don't validate" approach with explicit liberal vs strict comparisons
 */
function validateIndividualSignatureProfile(
  signature: Element,
  parentElement: Element,
): void {
  if (!signature) {
    throw new XMLValidationError("No signature");
  }
  if (!parentElement) {
    throw new XMLValidationError("No element to check against");
  }

  const signatureSelector = createSelector(signature);

  // Expect there to be one and only one SignedInfo
  // Liberal search first
  const foundSignedInfoNodes = signatureSelector.selectElements(
    ".//*[local-name()='SignedInfo']",
  );
  if (foundSignedInfoNodes.length !== 1) {
    if (foundSignedInfoNodes.length > 1) {
      // Check if these are direct children of this signature (single signature case)
      const directSignedInfoChildren =
        signatureSelector.selectElements("./ds:SignedInfo");
      if (directSignedInfoChildren.length > 1) {
        // Multiple SignedInfo as direct children - let the later check handle this
        // Skip the strict validation and go directly to the specific error at the end
        const multipleSignatures =
          signatureSelector.selectElements("./ds:SignedInfo[2]");
        if (multipleSignatures.length > 0) {
          throw new XMLValidationError(
            "response contained multiple SignedInfo elements in a single signature",
          );
        }
      } else {
        // Multiple SignedInfo found but not direct children - document level issue
        throw new XMLValidationError(
          "response contained multiple SignedInfo elements",
        );
      }
    } else {
      throw new XMLValidationError(
        `Expected exactly one SignedInfo element, found ${foundSignedInfoNodes.length}`,
      );
    }
  }

  // Strict search
  const expectedSignedInfo =
    signatureSelector.selectOptionalSingleElement("./ds:SignedInfo");
  if (!expectedSignedInfo) {
    throw new XMLValidationError("No SignedInfo");
  }

  // Verify liberal and strict find the same element
  if (foundSignedInfoNodes[0] !== expectedSignedInfo) {
    throw new XMLValidationError("Incorrect SignedInfo");
  }

  // Expect there to be one and only one reference node
  const signedInfoSelector = createSelector(expectedSignedInfo);

  // Liberal search for Reference
  const foundReferenceNodes = signatureSelector.selectElements(
    ".//*[local-name()='Reference']",
  );
  if (foundReferenceNodes.length !== 1) {
    throw new XMLValidationError(
      `Expected exactly one Reference element, found ${foundReferenceNodes.length}`,
    );
  }

  // Strict search for Reference
  const expectedReferenceNode =
    signedInfoSelector.selectOptionalSingleElement("./ds:Reference");
  if (!expectedReferenceNode) {
    throw new XMLValidationError("No Reference");
  }

  // Verify liberal and strict find the same element
  if (foundReferenceNodes[0] !== expectedReferenceNode) {
    throw new XMLValidationError("Incorrect Reference");
  }

  // Now reference logic validation
  // Most expressive URI attribute == Our expected URI attribute
  const foundUriAttributes = signatureSelector.selectAttributes(
    './/@*[local-name()="URI"]',
  );
  const expectedUriAttribute = expectedReferenceNode.getAttributeNode("URI");

  if (!expectedUriAttribute) {
    throw new XMLValidationError("No URI attribute");
  }

  // Verify only one URI attribute found and it matches expected
  if (
    foundUriAttributes.length !== 1 ||
    expectedUriAttribute !== foundUriAttributes[0]
  ) {
    throw new XMLValidationError("Incorrect URI attribute found");
  }

  // Verify URI attribute values match
  const expectedUri = expectedUriAttribute.value || "";
  if (expectedUri !== foundUriAttributes[0].value) {
    throw new XMLValidationError("URI attribute is ambiguous");
  }

  // We want URI to == our parent element
  // Processing: URIs need to be "#ID" or ""
  if (expectedUri === "") {
    // Empty URI should reference root document element
    const documentRoot =
      signature.ownerDocument?.documentElement ||
      signature.ownerDocument?.firstChild;
    if (documentRoot !== parentElement) {
      throw new XMLValidationError(
        "Doesn't dereference to root parent element (for empty URI)",
      );
    }
  } else if (expectedUri.startsWith("#")) {
    const referencedId = expectedUri.substring(1);

    // Validate the referenced ID is safe
    validateXMLIdentifier(referencedId);

    // Find all elements with this ID in the document
    const documentSelector = createSelector(
      signature.ownerDocument || signature,
    );
    const escapedId = escapeXPathAttribute(referencedId);
    const dereferencedElements = documentSelector.selectElements(
      `//*[@ID=${escapedId}]`,
    );

    if (dereferencedElements.length !== 1) {
      if (dereferencedElements.length === 0) {
        throw new XMLValidationError(
          `URI references non-existent ID: ${referencedId}`,
        );
      } else {
        throw new XMLValidationError(
          `Ambiguous reference URI: ${referencedId}, dereferences to ${dereferencedElements.length} elements`,
        );
      }
    }

    // Verify it dereferences to the parent element
    if (dereferencedElements[0] !== parentElement) {
      throw new XMLValidationError("Doesn't dereference to parent element");
    }
  } else {
    throw new XMLValidationError(`Malformed URI: ${expectedUri}`);
  }

  // Next verify the CanonicalizationMethod
  const foundC14nElements = signatureSelector.selectElements(
    ".//*[local-name()='CanonicalizationMethod']",
  );
  if (foundC14nElements.length !== 1) {
    throw new XMLValidationError(
      `Expected exactly one CanonicalizationMethod, found ${foundC14nElements.length}`,
    );
  }

  const expectedC14nElement = signedInfoSelector.selectOptionalSingleElement(
    "./ds:CanonicalizationMethod",
  );
  if (!expectedC14nElement) {
    throw new XMLValidationError("No CanonicalizationMethod");
  }

  // Verify liberal and strict find the same element
  if (foundC14nElements[0] !== expectedC14nElement) {
    throw new XMLValidationError("Unexpected CanonicalizationMethod");
  }

  const c14nAlgorithm = expectedC14nElement.getAttribute("Algorithm");
  const allowedC14nAlgorithms = [
    "http://www.w3.org/2001/10/xml-exc-c14n#",
    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
  ];

  if (!c14nAlgorithm || !allowedC14nAlgorithms.includes(c14nAlgorithm)) {
    throw new XMLValidationError(
      `Invalid CanonicalizationMethod algorithm: ${c14nAlgorithm}`,
    );
  }

  // Next verify the Transforms
  const foundTransforms = signatureSelector.selectElements(
    ".//*[local-name()='Transform']",
  );
  if (foundTransforms.length > 2) {
    throw new XMLValidationError(
      `Too many transforms: ${foundTransforms.length}. Maximum 2 allowed`,
    );
  }

  // Next verify the Transform Algorithm
  const allowedTransforms = [
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
    "http://www.w3.org/2001/10/xml-exc-c14n#",
    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
  ];

  foundTransforms.forEach((transform) => {
    const transformAlg = transform.getAttribute("Algorithm");
    if (!transformAlg || !allowedTransforms.includes(transformAlg)) {
      throw new XMLValidationError(
        `Unexpected transform algorithm: ${transformAlg}`,
      );
    }
  });

  // Validate SignatureMethod to block HMAC-based algorithms
  const foundSignatureMethods = signatureSelector.selectElements(
    ".//*[local-name()='SignatureMethod']",
  );
  if (foundSignatureMethods.length !== 1) {
    throw new XMLValidationError(
      `Expected exactly one SignatureMethod, found ${foundSignatureMethods.length}`,
    );
  }

  const expectedSignatureMethod =
    signedInfoSelector.selectOptionalSingleElement("./ds:SignatureMethod");
  if (!expectedSignatureMethod) {
    throw new XMLValidationError("No SignatureMethod");
  }

  // Verify liberal and strict find the same element
  if (foundSignatureMethods[0] !== expectedSignatureMethod) {
    throw new XMLValidationError("Unexpected SignatureMethod");
  }

  const signatureAlgorithm = expectedSignatureMethod.getAttribute("Algorithm");

  // Block HMAC-based signature methods as they are symmetric and unsuitable for SAML
  const blockedSignatureAlgorithms = [
    "http://www.w3.org/2000/09/xmldsig#hmac-sha1",
    "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
    "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384",
    "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512",
  ];

  if (
    signatureAlgorithm &&
    blockedSignatureAlgorithms.includes(signatureAlgorithm)
  ) {
    throw new XMLValidationError(
      `HMAC-based SignatureMethod blocked: ${signatureAlgorithm}`,
    );
  }

  // Validate allowed signature algorithms (RSA and ECDSA variants)
  const allowedSignatureAlgorithms = [
    "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
  ];

  if (
    !signatureAlgorithm ||
    !allowedSignatureAlgorithms.includes(signatureAlgorithm)
  ) {
    throw new XMLValidationError(
      `Invalid SignatureMethod algorithm: ${signatureAlgorithm}`,
    );
  }

  // Validate DigestMethod and DigestValue to prevent wrapping attacks
  validateDigestValueIntegrity(signatureSelector, signedInfoSelector);

  // Validate that all DigestValues in the parent element are properly contained within signatures
  validateAllDigestValuesAreInSignatures(parentElement);

  // Check for multiple SignedInfo nodes within this signature (redundant but keeping for completeness)
  const multipleSignatures =
    signatureSelector.selectElements("./ds:SignedInfo[2]");
  if (multipleSignatures.length > 0) {
    throw new XMLValidationError(
      "response contained multiple SignedInfo elements in a single signature",
    );
  }
}

/**
 * Validate DigestMethod and DigestValue integrity to prevent wrapping attacks
 * This addresses CVE-style attacks where DigestValue can be manipulated to reference different content
 */
function validateDigestValueIntegrity(
  signatureSelector: Selector,
  signedInfoSelector: Selector,
): void {
  // Find DigestMethod elements - liberal search within signature scope
  const foundDigestMethods = signatureSelector.selectElements(
    ".//*[local-name()='DigestMethod']",
  );
  if (foundDigestMethods.length !== 1) {
    throw new XMLValidationError(
      `Expected exactly one DigestMethod, found ${foundDigestMethods.length}`,
    );
  }

  const expectedDigestMethod = signedInfoSelector.selectElements(
    "./ds:Reference/ds:DigestMethod",
  );
  if (expectedDigestMethod.length !== 1) {
    throw new XMLValidationError("No DigestMethod in expected location");
  }

  // Verify liberal and strict find the same element
  if (foundDigestMethods[0] !== expectedDigestMethod[0]) {
    throw new XMLValidationError("DigestMethod location mismatch");
  }

  // Validate DigestMethod algorithm
  const digestAlgorithm = expectedDigestMethod[0].getAttribute("Algorithm");
  const allowedDigestAlgorithms = [
    "http://www.w3.org/2000/09/xmldsig#sha1",
    "http://www.w3.org/2001/04/xmlenc#sha256",
    "http://www.w3.org/2001/04/xmldsig-more#sha384",
    "http://www.w3.org/2001/04/xmldsig-more#sha512",
    "http://www.w3.org/2001/04/xmlenc#sha512", // Also allow this variant
  ];

  if (!digestAlgorithm || !allowedDigestAlgorithms.includes(digestAlgorithm)) {
    throw new XMLValidationError(
      `Invalid DigestMethod algorithm: ${digestAlgorithm}`,
    );
  }

  // Find DigestValue within this specific signature
  const foundDigestValues = signatureSelector.selectElements(
    ".//*[local-name()='DigestValue']",
  );
  if (foundDigestValues.length !== 1) {
    throw new XMLValidationError(
      `Expected exactly one DigestValue per signature, found ${foundDigestValues.length}. Multiple DigestValues can enable wrapping attacks`,
    );
  }

  const expectedDigestValue = signedInfoSelector.selectElements(
    "./ds:Reference/ds:DigestValue",
  );
  if (expectedDigestValue.length !== 1) {
    throw new XMLValidationError("No DigestValue in expected location");
  }

  // Verify within this signature, liberal and strict find the same element
  if (foundDigestValues[0] !== expectedDigestValue[0]) {
    throw new XMLValidationError(
      "DigestValue location mismatch - potential wrapping attack detected",
    );
  }

  // Validate DigestValue content is not empty
  const digestValueContent = expectedDigestValue[0].textContent?.trim();
  if (!digestValueContent) {
    throw new XMLValidationError("DigestValue cannot be empty");
  }

  // Ensure DigestValue contains only valid base64 characters
  const base64Pattern = /^[A-Za-z0-9+/]*={0,2}$/;
  if (!base64Pattern.test(digestValueContent)) {
    throw new XMLValidationError("DigestValue contains invalid characters");
  }
}

/**
 * Validate that all DigestValues in an element are properly contained within signatures
 * This prevents DigestValue wrapping attacks where malicious DigestValues are placed outside proper context
 */
function validateAllDigestValuesAreInSignatures(parentElement: Element): void {
  const parentSelector = createSelector(parentElement);

  // Find all DigestValues in the parent element
  const allDigestValues = parentSelector.selectElements(
    ".//*[local-name()='DigestValue']",
  );

  // Find all DigestValues that are properly contained within Reference elements
  const properDigestValues = parentSelector.selectElements(
    ".//ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue",
  );

  // All DigestValues should be in proper Reference locations
  if (allDigestValues.length !== properDigestValues.length) {
    throw new XMLValidationError(
      `Found ${allDigestValues.length} DigestValue elements but only ${properDigestValues.length} are in proper signature Reference context. Potential DigestValue wrapping attack detected`,
    );
  }

  // Verify each DigestValue is accounted for in proper locations
  for (const digestValue of allDigestValues) {
    if (!properDigestValues.includes(digestValue)) {
      throw new XMLValidationError(
        "DigestValue found outside proper signature Reference context - potential wrapping attack detected",
      );
    }
  }
}

/**
 * Validate forbidden elements within verified content only
 * Uses strict XPath and ensures liberal/strict consistency
 */
function validateForbiddenElementsInVerifiedContent(dom: Node): void {
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

  const elementSelector = createSelector(dom);

  forbiddenElements.forEach((elementName) => {
    // Use liberal search to find any forbidden elements
    const foundElements = elementSelector.selectElements(
      `//*[local-name()='${elementName}']`,
    );
    if (foundElements.length > 0) {
      throw new XMLValidationError(
        `Found ${foundElements.length} ${elementName} elements. None allowed in SAML responses`,
      );
    }
  });
}

/**
 * Create XPath for finding signatures that reference a specific ID
 * Uses safe ID validation to prevent injection
 */
function createSignatureXPath(nodeID: string): string {
  validateXMLIdentifier(nodeID);
  const escapedId = escapeXPathAttribute(nodeID);

  return (
    ".//*[" +
    "local-name(.)='Signature' and " +
    "namespace-uri(.)='http://www.w3.org/2000/09/xmldsig#' and " +
    `descendant::*[local-name(.)='Reference' and @URI=concat('#',${escapedId})]` +
    "]"
  );
}

// Clock skew tolerance in milliseconds
const CLOCK_SKEW_TOLERANCE_MS = 5 * 60 * 1000; // 5 minutes

// Default time function - can be mocked for testing
export const getCurrentTime = (): number => new Date().getTime();

function validateTimestamps(parsed: ParsedSAMLResponse): void {
  const now = getCurrentTime();

  // Only validate timestamps from signed assertions
  if (!parsed.assertionElement || !parsed.isAssertionSigned) {
    // Skip timestamp validation for unsigned assertions or encrypted assertions
    // Encrypted assertions will be validated after decryption by the consumer
    return;
  }

  const assertionSelector = createSelector(parsed.assertionElement);

  // Validate at most one Conditions element per SAML specification
  const conditionsElements =
    assertionSelector.selectElements("./saml:Conditions");
  if (conditionsElements.length > 1) {
    throw new XMLValidationError(
      `Found ${conditionsElements.length} Conditions elements in assertion. SAML specification allows at most one.`,
    );
  }

  // Check ~ NotBefore and NotOnOrAfter from signed assertion only
  const conditionsNotBefore = assertionSelector.selectOptionalSingleAttribute(
    "./saml:Conditions/@NotBefore",
  );
  const conditionsNotOnOrAfter =
    assertionSelector.selectOptionalSingleAttribute(
      "./saml:Conditions/@NotOnOrAfter",
    );

  if (conditionsNotBefore) {
    const notBeforeTime = new Date(conditionsNotBefore.value).getTime();
    if (now + CLOCK_SKEW_TOLERANCE_MS < notBeforeTime) {
      throw new SAMLAssertionNotYetValidError();
    }
  }

  if (conditionsNotOnOrAfter) {
    const notOnOrAfterTime = new Date(conditionsNotOnOrAfter.value).getTime();
    if (now - CLOCK_SKEW_TOLERANCE_MS > notOnOrAfterTime) {
      throw new SAMLAssertionExpiredError();
    }
  }

  // Check SubjectConfirmationData NotOnOrAfter from signed assertion only
  const subjectConfirmationNotOnOrAfter =
    assertionSelector.selectOptionalSingleAttribute(
      "./saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotOnOrAfter",
    );

  if (subjectConfirmationNotOnOrAfter) {
    const notOnOrAfterTime = new Date(
      subjectConfirmationNotOnOrAfter.value,
    ).getTime();
    if (now - CLOCK_SKEW_TOLERANCE_MS > notOnOrAfterTime) {
      throw new SAMLAssertionExpiredError();
    }
  }
}

/**
 * Validates a SAML response by first parsing verified elements, then validating only signed content
 * Implements strict security measures including XPath injection prevention and manual node traversal
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

  // CRITICAL: Block forbidden node types immediately after parsing via manual traversal
  blockForbiddenNodes(dom);

  // Validate forbidden elements within verified content only
  validateForbiddenElementsInVerifiedContent(dom);

  const selector = createSelector(dom);

  // Parse and identify the verified SAML structure using strict XPath
  const parsed = parseSAMLResponseStructure(selector);

  // Validate core requirements (signatures and status)
  validateCoreRequirements(parsed);

  validateTimestamps(parsed);

  // Validate signature profiles within signed elements only
  validateSignatureProfiles(parsed);
}

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
