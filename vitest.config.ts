import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    exclude: [
      ...configDefaults.exclude,
      "**/build/**",
      "**/dist/**",
    ],
    silent: "passed-only",
    reporters: ["default"],
    coverage: {
      include: ["lib/**/*.ts", "bin/**/*.ts"],
      exclude: ["test/**"],
      skipFull: true,
      reporter: ["text-summary", "html", "cobertura"],
      reportsDirectory: "coverage",
    },
  },
});
