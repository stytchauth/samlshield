import path from "path";
import { lintSAMLResponse, safeLintSAMLResponse } from "../../src";
import { ContractTestLoader } from "./loader";

describe("SAML Shield Contract Tests", () => {
  // Use absolute path to test data directory
  const dataPath = path.resolve(__dirname, "data/");
  const loader = new ContractTestLoader(dataPath);

  loader.loadTestCases().forEach((testCase) => {
    const testFn = testCase.isSkipped
      ? it.skip
      : testCase.isOnly
        ? it.only
        : it;

    testFn(testCase.name, async () => {
      const input = (await testCase.input) as any;

      if (testCase.shouldSucceed) {
        // Test should pass without throwing
        try {
          await lintSAMLResponse(input);

          // Also test the safe version
          const result = await safeLintSAMLResponse(input);
          expect(result.valid).toBe(true);
        } catch (error) {
          const errorMessage =
            error instanceof Error ? error.message : "Unknown error";
          console.error(`${testCase.debugInfo}\nUnexpected error:`, error);
          throw new Error(
            `Test case "${testCase.name}" should have succeeded but threw: ${errorMessage}`,
          );
        }
      } else {
        // Test should fail with expected error
        let thrownError: any = null;

        try {
          await lintSAMLResponse(input);
          throw new Error(
            `Test case "${testCase.name}" should have failed but succeeded`,
          );
        } catch (error) {
          thrownError = error;
        }

        // Test safe version returns error
        const result = await safeLintSAMLResponse(input);
        expect(result.valid).toBe(false);
        expect(result.errors).toBeDefined();
        expect(result.errors!.length).toBeGreaterThan(0);

        // Verify expected error message if specified
        if (testCase.expectedError && thrownError) {
          expect(thrownError.message).toContain(testCase.expectedError);
        }

        // Verify expected error code if specified
        if (testCase.expectedErrorCode && thrownError) {
          expect(thrownError.code).toBe(testCase.expectedErrorCode);
        }
      }
    });
  });
});
