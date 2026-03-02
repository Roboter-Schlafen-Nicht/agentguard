import { readFileSync } from "node:fs";
import { defineConfig } from "tsup";

const pkg = JSON.parse(
  readFileSync(new URL("package.json", import.meta.url), "utf-8"),
) as { version: string };

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  sourcemap: true,
  splitting: false,
  define: {
    __AGENTGUARD_VERSION__: JSON.stringify(pkg.version),
  },
});
