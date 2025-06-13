const { lintSAMLResponse, safeLintSAMLResponse } = require("../dist/index.js");

// Example SAML response (base64 encoded)
// This would normally come from your SAML identity provider
const exampleSAMLResponse =
  "PHNhbWwyOlJlc3BvbnNlIHhtbG5zOnNhbWwyPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6YXNzZXJ0aW9uIj4KPC9zYW1sMjpSZXNwb25zZT4=";

async function demonstrateBasicUsage() {
  console.log("=== Basic SAML Linting Demo ===\n");

  // Method 1: Using the throwing version
  console.log("1. Using lintSAMLResponse (throws on error):");
  try {
    await lintSAMLResponse({
      response_xml: exampleSAMLResponse,
    });
    console.log("✅ SAML response is valid!");
  } catch (error) {
    console.log("❌ SAML validation failed:", error.message);
    console.log("   Error code:", error.code);
    if (error.details) {
      console.log("   Details:", JSON.stringify(error.details, null, 2));
    }
  }

  console.log("\n2. Using safeLintSAMLResponse (returns result object):");

  // Method 2: Using the safe version that returns a result
  const result = await safeLintSAMLResponse({
    response_xml: exampleSAMLResponse,
  });

  if (result.valid) {
    console.log("✅ SAML response is valid!");
  } else {
    console.log("❌ SAML validation failed");
    console.log("   Errors:", result.errors);
  }

  // Example of handling different error types
  console.log("\n3. Demonstrating error handling:");

  try {
    await lintSAMLResponse({
      response_xml: "", // Empty response to trigger validation error
    });
  } catch (error) {
    console.log("Caught expected error:", error.constructor.name);
    console.log("Message:", error.message);
  }
}

// Run the demo
demonstrateBasicUsage().catch(console.error);
