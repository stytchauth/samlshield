import * as fs from "fs";
import path from "node:path";

const BASE64_DIRECTIVE = "!embed:base64:";
const EMBED_DIRECTIVE = "!embed:file://";
const EMBED_BASE64_DIRECTIVE = "!embed:base64:file://";

type TestCase = {
  only?: boolean;
  skip?: boolean;
  name?: string;
  description?: string;
  input?: Record<string, unknown>;
  mockTime?: string;
  shouldSucceed?: boolean;
  expectedError?: string;
  expectedErrorCode?: string;
};

export class ContractTestCase {
  public fileContents: TestCase;

  constructor(
    public testDir: string,
    public testFile: string,
  ) {
    this.fileContents = JSON.parse(
      fs.readFileSync(testFile).toString(),
    ) as TestCase;
  }

  get isOnly() {
    return !!this.fileContents.only;
  }

  get isSkipped() {
    return !!this.fileContents.skip;
  }

  get name() {
    return (
      this.fileContents.name ||
      this.testFile
        .replace(path.join(__dirname, "data"), "")
        .replace(".test.json", "")
        .split(path.sep)
        .join(" ")
    );
  }

  get description() {
    return this.fileContents.description || this.name;
  }

  get debugInfo() {
    return "\t" + "[Test Case INPUT]\n" + "\tfile://" + this.testFile;
  }

  get shouldSucceed() {
    return this.fileContents.shouldSucceed !== false; // Default to true
  }

  get expectedError() {
    return this.fileContents.expectedError;
  }

  get expectedErrorCode() {
    return this.fileContents.expectedErrorCode;
  }

  get mockTime() {
    return this.fileContents.mockTime;
  }

  get input() {
    if (typeof this.fileContents.input !== "object") {
      throw Error("Missing input for " + this.testFile);
    }
    return ContractTestCase.resolveEmbeds(
      this.testDir,
      this.fileContents.input,
    );
  }

  private static async resolveEmbeds(
    root: string,
    input: Array<unknown> | Record<string, unknown> | string,
  ): Promise<unknown> {
    if (typeof input === "string") {
      if (input.startsWith(EMBED_DIRECTIVE)) {
        const embedLocation = path.join(
          root,
          input.replace(EMBED_DIRECTIVE, ""),
        );
        return await fs.promises
          .readFile(embedLocation)
          .then((buf) => buf.toString());
      }
      if (input.startsWith(EMBED_BASE64_DIRECTIVE)) {
        const embedLocation = path.join(
          root,
          input.replace(EMBED_BASE64_DIRECTIVE, ""),
        );
        return await fs.promises
          .readFile(embedLocation)
          .then((buf) => buf.toString("base64"));
      }
      if (input.startsWith(BASE64_DIRECTIVE)) {
        return Buffer.from(input.replace(BASE64_DIRECTIVE, "")).toString(
          "base64",
        );
      }
      return input;
    }

    if (Array.isArray(input)) {
      return Promise.all(
        input.map(ContractTestCase.resolveEmbeds.bind(null, root)),
      );
    }

    if (input === null) {
      return null;
    }

    if (typeof input === "object") {
      const output: Record<string, unknown> = {};
      for (const key in input) {
        output[key] = await ContractTestCase.resolveEmbeds(
          root,
          input[key] as Record<string, unknown>,
        );
      }
      return output;
    }

    return input;
  }
}

export class ContractTestLoader {
  constructor(public root: string) {}

  loadTestCases() {
    const testCases = [];
    const stack = [this.root];

    while (stack.length > 0) {
      const dirPath = stack.shift() as string;
      const files = fs
        .readdirSync(dirPath)
        .map((file) => path.join(dirPath, file));
      for (const file of files) {
        const stats = fs.statSync(file);
        if (stats.isDirectory()) {
          stack.push(file);
        } else if (file.endsWith(".test.json")) {
          testCases.push(new ContractTestCase(path.dirname(file), file));
        }
      }
    }
    return testCases;
  }
}
