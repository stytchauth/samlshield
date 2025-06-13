import { DOMParser } from "@xmldom/xmldom";
import * as xpath from "xpath";

// Type for XML parsing errors
interface ParseError extends Error {
  line?: number;
  col?: number;
}
import {
  XMLExpectedOptionalSingletonError,
  XMLExpectedSingletonError,
  XMLExternalEntitiesForbiddenError,
  XMLValidationError,
  XPathError,
} from "./errors";

const selector = xpath.useNamespaces({
  md: "urn:oasis:names:tc:SAML:2.0:metadata",
  NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:*",
  saml: "urn:oasis:names:tc:SAML:2.0:assertion",
  samlp: "urn:oasis:names:tc:SAML:2.0:protocol",
  saml2: "urn:oasis:names:tc:SAML:2.0:assertion",
  saml2p: "urn:oasis:names:tc:SAML:2.0:protocol",
  ds: "http://www.w3.org/2000/09/xmldsig#",
  sig: "http://www.w3.org/2000/09/xmldsig#",
});

type SelectedValue = string | number | boolean | Node;

// All the DOM Node Types available in an XML document
// Ref: https://developer.mozilla.org/en-US/docs/Web/API/Node/nodeType
enum NODE_TYPE {
  STRING = "STRING",
  NUMBER = "NUMBER",
  BOOLEAN = "BOOLEAN",
  ELEMENT_NODE = "ELEMENT_NODE",
  ATTRIBUTE_NODE = "ATTRIBUTE_NODE",
  TEXT_NODE = "TEXT_NODE",
  CDATA_SECTION_NODE = "CDATA_SECTION_NODE",
  ENTITY_REFERENCE_NODE = "ENTITY_REFERENCE_NODE",
  ENTITY_NODE = "ENTITY_NODE",
  PROCESSING_INSTRUCTION_NODE = "PROCESSING_INSTRUCTION_NODE",
  COMMENT_NODE = "COMMENT_NODE",
  DOCUMENT_NODE = "DOCUMENT_NODE",
  DOCUMENT_TYPE_NODE = "DOCUMENT_TYPE_NODE",
  DOCUMENT_FRAGMENT_NODE = "DOCUMENT_FRAGMENT_NODE",
  NOTATION_NODE = "NOTATION_NODE",
  UNKNOWN = "UNKNOWN",
}

function getTypeofEl(el: SelectedValue): NODE_TYPE {
  if (typeof el === "string") {
    return NODE_TYPE.STRING;
  }
  if (typeof el === "number") {
    return NODE_TYPE.NUMBER;
  }
  if (typeof el === "boolean") {
    return NODE_TYPE.BOOLEAN;
  }

  switch (el.nodeType) {
    case el.ELEMENT_NODE:
      return NODE_TYPE.ELEMENT_NODE;
    case el.ATTRIBUTE_NODE:
      return NODE_TYPE.ATTRIBUTE_NODE;
    case el.TEXT_NODE:
      return NODE_TYPE.TEXT_NODE;
    case el.CDATA_SECTION_NODE:
      return NODE_TYPE.CDATA_SECTION_NODE;
    case el.ENTITY_REFERENCE_NODE:
      return NODE_TYPE.ENTITY_REFERENCE_NODE;
    case el.ENTITY_NODE:
      return NODE_TYPE.ENTITY_NODE;
    case el.PROCESSING_INSTRUCTION_NODE:
      return NODE_TYPE.PROCESSING_INSTRUCTION_NODE;
    case el.COMMENT_NODE:
      return NODE_TYPE.COMMENT_NODE;
    case el.DOCUMENT_NODE:
      return NODE_TYPE.DOCUMENT_NODE;
    case el.DOCUMENT_TYPE_NODE:
      return NODE_TYPE.DOCUMENT_TYPE_NODE;
    case el.DOCUMENT_FRAGMENT_NODE:
      return NODE_TYPE.DOCUMENT_FRAGMENT_NODE;
    case el.NOTATION_NODE:
      return NODE_TYPE.NOTATION_NODE;
  }
  return NODE_TYPE.UNKNOWN;
}

const attributesXPathTypeGuard = (
  values: SelectedValue[],
): values is Attr[] => {
  return values.every(
    (value) => getTypeofEl(value) === NODE_TYPE.ATTRIBUTE_NODE,
  );
};

const elementsXPathTypeGuard = (
  values: SelectedValue[],
): values is Element[] => {
  return values.every((value) => getTypeofEl(value) === NODE_TYPE.ELEMENT_NODE);
};

const commentsXPathTypeGuard = (
  values: SelectedValue[],
): values is Element[] => {
  return values.every((value) => getTypeofEl(value) === NODE_TYPE.COMMENT_NODE);
};

const textXPathTypeGuard = (values: SelectedValue[]): values is Text[] => {
  return values.every((value) => getTypeofEl(value) === NODE_TYPE.TEXT_NODE);
};

const processingInstructionsXPathTypeGuard = (
  values: SelectedValue[],
): values is Element[] => {
  return values.every(
    (value) => getTypeofEl(value) === NODE_TYPE.PROCESSING_INSTRUCTION_NODE,
  );
};

export class Selector {
  constructor(public dom: Node) {}

  selectAttributes = (xpath: string): Attr[] => {
    const result = selector(xpath, this.dom) as SelectedValue[];
    if (!attributesXPathTypeGuard(result)) {
      throw new XPathError(
        xpath,
        NODE_TYPE.ATTRIBUTE_NODE,
        getTypeofEl(result[0]),
      );
    }
    return result;
  };

  selectOptionalSingleAttribute = (xpath: string): Attr | null => {
    const attrs = this.selectAttributes(xpath);
    if (attrs.length === 0) {
      return null;
    }
    if (attrs.length > 1) {
      throw new XMLExpectedOptionalSingletonError(
        xpath,
        NODE_TYPE.ATTRIBUTE_NODE,
        attrs.length,
      );
    }
    return attrs[0];
  };

  selectSingleAttribute = (xpath: string): Attr => {
    const attrs = this.selectAttributes(xpath);
    if (attrs.length != 1) {
      throw new XMLExpectedSingletonError(
        xpath,
        NODE_TYPE.ATTRIBUTE_NODE,
        attrs.length,
      );
    }
    return attrs[0];
  };

  selectComments = (xpath: string): Element[] => {
    const result = selector(xpath, this.dom) as SelectedValue[];
    if (!commentsXPathTypeGuard(result)) {
      throw new XPathError(
        xpath,
        NODE_TYPE.COMMENT_NODE,
        getTypeofEl(result[0]),
      );
    }
    return result;
  };

  selectElements = (xpath: string): Element[] => {
    const result = selector(xpath, this.dom) as SelectedValue[];
    if (!elementsXPathTypeGuard(result)) {
      throw new XPathError(
        xpath,
        NODE_TYPE.ELEMENT_NODE,
        getTypeofEl(result[0]),
      );
    }
    return result;
  };

  selectOptionalSingleElement = (xpath: string): Element | null => {
    const els = this.selectElements(xpath);
    if (els.length === 0) {
      return null;
    }
    if (els.length > 1) {
      throw new XMLExpectedOptionalSingletonError(
        xpath,
        NODE_TYPE.ELEMENT_NODE,
        els.length,
      );
    }
    return els[0];
  };

  selectSingleElement = (xpath: string): Element => {
    const els = this.selectElements(xpath);
    if (els.length != 1) {
      throw new XMLExpectedSingletonError(
        xpath,
        NODE_TYPE.ELEMENT_NODE,
        els.length,
      );
    }
    return els[0];
  };

  selectTexts = (xpath: string): Text[] => {
    const result = selector(xpath, this.dom) as SelectedValue[];
    if (!textXPathTypeGuard(result)) {
      throw new XPathError(xpath, NODE_TYPE.TEXT_NODE, getTypeofEl(result[0]));
    }
    return result;
  };

  selectSingleText = (xpath: string): Text => {
    const texts = this.selectTexts(xpath);
    if (texts.length != 1) {
      throw new XMLExpectedSingletonError(
        xpath,
        NODE_TYPE.TEXT_NODE,
        texts.length,
      );
    }
    return texts[0];
  };

  selectProcessingInstructions = (xpath: string): Element[] => {
    const result = selector(xpath, this.dom) as SelectedValue[];
    if (!processingInstructionsXPathTypeGuard(result)) {
      throw new XPathError(
        xpath,
        NODE_TYPE.PROCESSING_INSTRUCTION_NODE,
        getTypeofEl(result[0]),
      );
    }
    return result;
  };
}

export const createSelector = (dom: Node) => new Selector(dom);

export const xmlStringToDOM = (xmlDocString: string): Node => {
  // Throws a new XMLDOM sax ParseError which causes the internal
  // XMLDOM parser to immediately re-throw
  // Other errors will be caught and processed, which destroys some of the error context
  const bailImmediately = (msg: string): never => {
    const error = new Error(msg) as ParseError;
    throw error;
  };

  const parser = new DOMParser({
    // Copied from Node-SAML: setting this gives better error messages in the underlying lib
    locator: {},
    errorHandler: {
      error: bailImmediately,
      fatalError: bailImmediately,
    },
  });

  try {
    return parser.parseFromString(xmlDocString, "application/xml");
  } catch (e: unknown) {
    coerceXMLDOMError(e);
  }
};

function coerceXMLDOMError(err: unknown): never {
  if (!(err instanceof Error)) {
    // This should never happen, but is required for typescript guarantees
    throw err;
  }

  // The following XMLDOM errors are taken from grepping through
  // XMLDOM for all invocations of errorHandler.error and errorHandler.fatalError

  if (err.message.includes("entity not found:")) {
    throw new XMLExternalEntitiesForbiddenError();
  }

  if (err.message.includes("unexpected end of input")) {
    throw new XMLValidationError(
      "found unexpected end of input while evaluating XML",
    );
  }
  if (err.message.includes("Unclosed comment")) {
    throw new XMLValidationError(
      "found unexpected unclosed comment while evaluating XML",
    );
  }
  if (err.message.includes("end tag name")) {
    throw new XMLValidationError(
      "found mismatched tag names while evaluating XML",
    );
  }
  if (/Attribute .* redefined/.test(err.message)) {
    throw new XMLValidationError(
      "found duplicate attribute while evaluating XML",
    );
  }

  // A sample of more strict XMLDOM errors are taken from grepping through
  // XMLDOM for all invocations of throw new
  console.error("[XML VALIDATION] invalid XML:", err);
  throw new XMLValidationError("could not parse XML");
}

export const xmlBase64ToDOM = (xmlDocBase64Encoded: string): Node => {
  const decoded = Buffer.from(xmlDocBase64Encoded, "base64").toString();
  return xmlStringToDOM(decoded);
};
