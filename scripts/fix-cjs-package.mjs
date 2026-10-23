import { writeFileSync } from "node:fs";

// tsc emits plain .js files; the root package.json declares "type": "module",
// so the CJS build needs its own manifest to be require()-able.
writeFileSync(new URL("../dist/cjs/package.json", import.meta.url), JSON.stringify({ type: "commonjs" }, null, 2) + "\n");
