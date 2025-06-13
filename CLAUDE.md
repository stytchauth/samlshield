# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Development Commands

### Building and Testing

- `yarn build` - Compile TypeScript to dist/
- `yarn test` - Run all tests (unit and contract tests)
- `yarn lint` - ESLint TypeScript files in src/
- `yarn format` - Format code with Prettier

### Test Development

When adding tests, use the contract testing pattern:

- Add XML test data to `test/contract/data/` subdirectories
- Create `.test.json` files with test metadata
- Use embed directives like `!embed:base64:file://filename.xml` for test data

## Architecture

### Core Components

- `src/lint.ts` - Main SAML validation logic with `lintSAMLResponse()` and `safeLintSAMLResponse()`
- `src/xml.ts` - XML parsing utilities with XPath selectors and SAML namespace support
- `src/errors.ts` - Comprehensive error class hierarchy for different validation failures
- `src/index.ts` - Public API exports

### Security-First Design

This library validates SAML responses against multiple attack vectors:

- XXE (XML External Entity) attacks
- XML comment injection (CVE-2017-11428 family)
- Multiple SignedInfo element attacks
- Processing instruction injection (always blocked)
- Missing signature validation

### Contract Testing Pattern

The codebase uses data-driven contract tests in `test/contract/`:

- `data/valid/` - Tests that should pass
- `data/error_cases/` - Structural validation failures
- `data/vulnerabilities/` - Security vulnerability detection tests
- `loader.ts` - Test case loading with embed directive processing
- `runner.test.ts` - Test execution engine

### TypeScript Configuration

- Main config: `tsconfig.json` (excludes test files)
- Output: CommonJS modules to `dist/` with declarations

When making changes, always run the full test suite (`yarn test`) to ensure security validations remain intact.
