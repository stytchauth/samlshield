const {
  lintSAMLResponse,
  safeLintSAMLResponse,
  ValidationError,
} = require("../dist/index.js");

describe("SAML Shield Basic Tests", () => {
  test("should throw ValidationError for empty response", async () => {
    await expect(lintSAMLResponse({ response_xml: "" })).rejects.toThrow(
      "missing required field: SAMLResponse",
    );
  });

  test("should throw ValidationError for missing response_xml", async () => {
    await expect(lintSAMLResponse({})).rejects.toThrow(
      "missing required field: SAMLResponse",
    );
  });

  test("safeLintSAMLResponse should return error object instead of throwing", async () => {
    const result = await safeLintSAMLResponse({ response_xml: "" });

    expect(result.valid).toBe(false);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toContain("missing required field: SAMLResponse");
  });

  test("should detect invalid XML structure", async () => {
    const invalidXML = Buffer.from(
      "<invalid>not a saml response</invalid>",
    ).toString("base64");

    await expect(
      lintSAMLResponse({ response_xml: invalidXML }),
    ).rejects.toThrow("document does not contain a SAML Response element");
  });
});
