import path from "path";
import { safeValidateSAMLResponse, validateSAMLResponse } from "../../src";
import * as validateModule from "../../src/validate";
import { ContractTestLoader } from "./loader";

// Mock the getCurrentTime function using jest.spyOn
const mockGetCurrentTime = jest.spyOn(validateModule, "getCurrentTime");

describe("SAML Shield Contract Tests", () => {
  // Use absolute path to test data directory
  const dataPath = path.resolve(__dirname, "data/");
  const loader = new ContractTestLoader(dataPath);

  // For existing tests with old SAML data, we need to set a time within their validity window
  // Since test data spans Nov 4-24, 2022, use Nov 20 which should work for most test data
  const MOCK_TIME = new Date("2022-11-20T12:00:00.000Z").getTime();

  beforeAll(() => {
    // For existing test data (with 2022 timestamps), set mock time to make SAML data valid
    // Only specific tests with mockTime will override this for timestamp validation testing
    mockGetCurrentTime.mockReturnValue(MOCK_TIME);
  });

  afterAll(() => {
    jest.restoreAllMocks();
  });

  loader.loadTestCases().forEach((testCase) => {
    const testFn = testCase.isSkipped
      ? it.skip
      : testCase.isOnly
        ? it.only
        : it;

    testFn(testCase.name, async () => {
      const input = (await testCase.input) as any;

      // Mock time if specified in test case
      if (testCase.mockTime) {
        const mockTimeMs = new Date(testCase.mockTime).getTime();
        mockGetCurrentTime.mockReturnValue(mockTimeMs);
      }

      const validateArgs = {
        response_xml: input.response_xml,
      };

      if (testCase.shouldSucceed) {
        // Test should pass without throwing
        try {
          await validateSAMLResponse(validateArgs);

          // Also test the safe version
          const result = await safeValidateSAMLResponse(validateArgs);
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
          await validateSAMLResponse(validateArgs);
          throw new Error(
            `Test case "${testCase.name}" should have failed but succeeded`,
          );
        } catch (error) {
          thrownError = error;
        }

        // Test safe version returns error
        const result = await safeValidateSAMLResponse(validateArgs);
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

      // Reset time mock after each test to prevent interference
      if (testCase.mockTime) {
        mockGetCurrentTime.mockReturnValue(MOCK_TIME);
      }
    });
  });
});
