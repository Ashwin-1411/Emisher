import { copyFileSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { defineConfig, type Plugin } from "vite";

// Two builds are needed because a Chrome content script is a classic script: it cannot
// `import` shared chunks, so it must be bundled alone as one self-contained IIFE.
//   vite build                -> popup, options, background service worker (ES modules)
//   vite build --mode content -> content.js (IIFE)
function copyManifest(): Plugin {
  return {
    name: "copy-manifest",
    closeBundle() {
      mkdirSync("dist", { recursive: true });
      copyFileSync("manifest.json", "dist/manifest.json");
    },
  };
}

export default defineConfig(({ mode }) => {
  if (mode === "content") {
    return {
      plugins: [copyManifest()],
      publicDir: false,
      build: {
        emptyOutDir: false,
        lib: {
          entry: resolve(__dirname, "src/content/index.ts"),
          formats: ["iife"],
          name: "PeaContent",
          fileName: () => "content.js",
        },
      },
    };
  }
  return {
    base: "./",
    plugins: [copyManifest()],
    build: {
      rollupOptions: {
        input: {
          popup: resolve(__dirname, "popup.html"),
          options: resolve(__dirname, "options.html"),
          background: resolve(__dirname, "src/background/index.ts"),
        },
        output: {
          entryFileNames: "[name].js",
          chunkFileNames: "chunks/[name].js",
          assetFileNames: "assets/[name][extname]",
        },
      },
    },
    test: { environment: "jsdom", include: ["tests/**/*.test.ts"] },
  };
});
