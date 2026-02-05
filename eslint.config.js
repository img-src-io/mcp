import eslint from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  eslint.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // Allow unused vars prefixed with underscore
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      // Allow explicit any in specific cases
      "@typescript-eslint/no-explicit-any": "warn",
      // Consistent type imports
      "@typescript-eslint/consistent-type-imports": [
        "error",
        { prefer: "type-imports" },
      ],
      // Allow non-null assertions where we've validated
      "@typescript-eslint/no-non-null-assertion": "off",
      // Allow deprecated APIs (MCP SDK deprecation warnings)
      "@typescript-eslint/no-deprecated": "warn",
    },
  },
  {
    ignores: ["node_modules/**", "dist/**", "*.config.js"],
  }
);
