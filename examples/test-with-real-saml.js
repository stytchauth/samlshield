const { validateSAMLResponse } = require("../dist/index.js");

// Real SAML response from test data (base64 encoded)
const realSAMLResponse = Buffer.from(
  `<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6" Version="2.0" IssueInstant="2014-07-17T01:01:48Z" Destination="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75" Version="2.0" IssueInstant="2014-07-17T01:01:48Z">
    <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
    <saml:Subject>
      <saml:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="2030-01-18T06:21:48Z" Recipient="http://sp.example.com/demo1/index.php?acs" InResponseTo="ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="2014-07-17T01:01:18Z" NotOnOrAfter="2030-01-18T06:21:48Z">
      <saml:AudienceRestriction>
        <saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="2014-07-17T01:01:48Z" SessionNotOnOrAfter="2030-07-17T09:01:48Z" SessionIndex="_be9967abd904ddcae3c0eb4189adbe3f71e327cf93">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="uid" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="mail" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">test@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="eduPersonAffiliation" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue xsi:type="xs:string">users</saml:AttributeValue>
        <saml:AttributeValue xsi:type="xs:string">examplerole1</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`,
).toString("base64");

async function testWithRealSAML() {
  console.log("=== Testing with Real SAML Response ===\n");

  try {
    console.log("Testing valid SAML response structure...");
    await validateSAMLResponse({
      response_xml: realSAMLResponse,
    });
    console.log("✅ Real SAML response passed all security checks!");
  } catch (error) {
    console.log("❌ Real SAML validation failed:", error.message);
    console.log("   Error code:", error.code);
    console.log("   Details:", JSON.stringify(error, null, 2));
    if (error.details) {
      console.log("   Details:", JSON.stringify(error.details, null, 2));
    }
  }

  // Test with a SAML response that has XML comments (security vulnerability)
  console.log("\n=== Testing Security Vulnerability Detection ===\n");

  const maliciousSAMLWithComments = Buffer.from(
    `<?xml version="1.0" encoding="UTF-8" standalone="no"?><saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://775f-75-63-30-121.ngrok.io/callback" ID="_0a39929628bc6d460c94ceb8c19a16db" InResponseTo="804059652377" IssueInstant="2022-11-22T20:27:15.882Z" Version="2.0"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://accounts.google.com/o/saml2?idpid=C02ji0uvf</saml2:Issuer><saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status><saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_aab802ce974917756ba2f63d1c2985b5" IssueInstant="2022-11-22T20:27:15.882Z" Version="2.0"><!-- This is a malicious comment --><saml2:Issuer>https://accounts.google.com/o/saml2?idpid=C02ji0uvf</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#_aab802ce974917756ba2f63d1c2985b5"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>zHhpph/xtjI6HHF2J0LBFAXzTNJoEb0ndJj1ODZL87Q=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>nhOxTX8oYhLhhdAp5wqEJfTv+r0vJlSydIsGVNDPXB8RX9utc+Fwstf3698YSI8pWGrhn94S9mYnAT/YfwioRJH7SUE0fAyUxo+DjsYgVn0da6r3dAh9J/Fe653RGo3Qgy9X1edoZJusN5gcIL4HHPpVFvMxRs7JsPdmIFsRaE916IAtQei3KITYcNkEw7wGNHNx8RqfL7CA0P5oWLrmnq6t2IZNYHz8ZIrViUg62FmxKHdgtVlHtIMmXO2uWD/UgHN7oUHtxDXTNv0kMaDKRUuFDXtw/AwjHPqLR3hCKlTT7Ts0Y7aBT21QCrXs+mNL1mn1bXwSPKZm2WNzAAZAEg==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509SubjectName>ST=California,C=US,OU=Google For Work,CN=Google,L=Mountain View,O=Google Inc.</ds:X509SubjectName><ds:X509Certificate>MIIDdDCCAlygAwIBAgIGAYSgi9d6MA0GCSqGSIb3DQEBCwUAMHsxFDASBgNVBAoTC0dvb2dsZSBJbmMuMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MQ8wDQYDVQQDEwZHb29nbGUxGDAWBgNVBAsTD0dvb2dsZSBGb3IgV29yazELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWEwHhcNMjIxMTIyMTgxMzQ5WhcNMjcxMTIxMTgxMzQ5WjB7MRQwEgYDVQQKEwtHb29nbGUgSW5jLjEWMBQGA1UEBxMNTW91bnRhaW4gVmlldzEPMA0GA1UEAxMGR29vZ2xlMRgwFgYDVQQLEw9Hb29nbGUgRm9yIFdvcmsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn9dOryAKN3ejQRaO2eE64fc3gQofDk1esXp8ANnuDxfzWUXKe8gshligszaq05xNTPMJV9isb124nWsVqqPzR7z2mjg/3wR/U2vELLTYg0en/ToPXMax0+3rFM3ClEeWAiwErnTW9M482zOwOJICrdkM9JQ71QuU1Y6qYfHv0v8ZGWXOEmwuUeG3FYcgfGdTfndgbhxOYTJ8WR6cvoaO3CN/qvcy5XAZnj1UswfV+l7bZhYBjkbybajc9VTdnbqp5vE07qdbGWDEHFNkoteenr61JWLAIi8hDLMEWDXU3umibNjq+FSRxIUErDytczChuGyUpKb2B0uIlzn0sqrpywIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAlF/7umzkl90jgRI4gpO4sajw1v63hrhnu+OfXiv1T8OZuYlh9qqU+XWFwPtW19i2Vlev5DVPHHDukpjJcnVz14cnnqUmt0CrspOQm4+y4dKRimKAzof964/BIvcVIz/m7UEQiQ80EAWUgvjwa/WIl1fu2bIbS4AykJ5uw6FyqGVMrrYg38CfaW9655w/8ihSgJvj6qioBYe90SAzwTomOeV5msyawxUQYF5InCLYOejinkOlsFrhqAI71t8Uy+VpqxwtsN1G3vfDvTY1gG7ju8n1YFwvVm9Z6BKpD0hbvToEpHDFcUzUDC3qAjdvBPDRqyfAeNUBJBsYrARXNqSyr</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">mgerber@stytchdev.com</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData InResponseTo="804059652377" NotOnOrAfter="2022-11-22T20:32:15.882Z" Recipient="https://775f-75-63-30-121.ngrok.io/callback"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="2022-11-22T20:22:15.882Z" NotOnOrAfter="2022-11-22T20:32:15.882Z"><saml2:AudienceRestriction><saml2:Audience>entity_id</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="2022-11-22T19:09:40.000Z" SessionIndex="_aab802ce974917756ba2f63d1c2985b5"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion></saml2p:Response>`,
  ).toString("base64");

  try {
    console.log("Testing SAML response with malicious XML comments...");
    await validateSAMLResponse({
      response_xml: maliciousSAMLWithComments,
    });
    console.log("❌ This should not happen - malicious SAML was accepted!");
  } catch (error) {
    console.log(
      "✅ Successfully detected and blocked malicious SAML response!",
    );
    console.log("   Error:", error.message);
    console.log("   Security issue detected:", error.code);
  }
}

// Run the test
testWithRealSAML().catch(console.error);
