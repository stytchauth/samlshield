module.exports = {
  extends: ["plugin:@typescript-eslint/recommended", "prettier"],
  parser: "@typescript-eslint/parser",
  parserOptions: {
    ecmaFeatures: {
      jsx: true,
    },
    ecmaVersion: 2018,
    sourceType: "module",
  },
  plugins: ["prettier"],
  rules: {
    "@typescript-eslint/ban-ts-comment": "off",
    "@typescript-eslint/no-explicit-any": "error",
    "prettier/prettier": ["error"],
  },
  overrides: [
    {
      files: ["*.test.ts"],
      rules: {
        "@typescript-eslint/no-explicit-any": 0,
      },
    },
    {
      files: ["**/__mocks__/*.ts"],
      rules: {
        "@typescript-eslint/explicit-module-boundary-types": 0,
      },
    },
  ],
};
