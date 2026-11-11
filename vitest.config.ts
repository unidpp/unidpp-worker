import { defineConfig } from "vitest/config";
import wasm from "vite-plugin-wasm";

// The goldens are imported as text (wrangler's Text rule does this at
// deploy time); vitest needs the same treatment.
export default defineConfig({
  plugins: [
    wasm(),
    {
      name: "yaml-as-text",
      enforce: "pre",
      transform(code, id) {
        if (id.endsWith(".yaml")) {
          return `export default ${JSON.stringify(code)};`;
        }
        return null;
      },
    },
  ],
});
