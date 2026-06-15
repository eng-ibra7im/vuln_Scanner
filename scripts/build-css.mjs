import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");
const sourceFiles = ["web/main.css", "web/profile-overrides.css"].map((file) =>
  path.join(rootDir, file),
);
const outputFile = path.join(rootDir, "web", "styles.min.css");

function minifyCss(css) {
  return css
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/\r\n?/g, "\n")
    .replace(/\s+/g, " ")
    .replace(/\s*([{}:;,>~])\s*/g, "$1")
    .replace(/;}/g, "}")
    .trim();
}

const cssChunks = await Promise.all(
  sourceFiles.map((filePath) => readFile(filePath, "utf8")),
);
const combinedCss = cssChunks.join("\n");
const minifiedCss = `${minifyCss(combinedCss)}\n`;

await writeFile(outputFile, minifiedCss, "utf8");

const sourceBytes = Buffer.byteLength(combinedCss, "utf8");
const outputBytes = Buffer.byteLength(minifiedCss, "utf8");

console.log(
  `Built ${path.relative(rootDir, outputFile)} (${outputBytes} bytes from ${sourceBytes} bytes)`,
);
