/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import cssInjectedByJsPlugin from "vite-plugin-css-injected-by-js";
import ViteYaml from "@modyfi/vite-plugin-yaml";
import dts from "vite-plugin-dts";

import packageJson from "./package.json";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    react(),
    ViteYaml(),
    cssInjectedByJsPlugin(),
    dts({
      insertTypesEntry: true,
    }),
  ],
  build: {
    lib: {
      entry: "index.ts",
      name: packageJson.name,
      fileName: (format) => `${packageJson.name}.${format}.js`,
    },
    rollupOptions: {
      external: ["react", "react-dom", "react-i18next", "react-bootstrap"],
      output: {
        globals: {
          react: "React",
          "react-dom": "ReactDOM",
          "react-i18next": "reactI18next",
          "react-bootstrap": "reactBootstrap",
        },
      },
    },
  },
  css: {
    postcss: {
      plugins: [
        {
          postcssPlugin: "editor-stacks-css-scope",
          Once(root, { result }) {
            const fromPath = result.opts.from || "";
            const isStacksCss = fromPath.includes(
              "@stackoverflow/stacks/dist/css/stacks.css",
            );
            if (!isStacksCss) return;

            root.walkRules((rule) => {
              if (
                rule.parent?.type === "atrule" &&
                rule.parent.name === "keyframes"
              ) {
                return;
              }

              const scopedSelectors = rule.selectors.map((sel) => {
                let s = sel;

                s = s
                  .replace(/\bbody\b/g, ":where(.editor-stacks-scope)")
                  .replace(/\bhtml\b/g, ":where(.editor-stacks-scope)")
                  .replace(/:root\b/g, ":where(.editor-stacks-scope)");

                if (
                  s.includes(":where(.editor-stacks-scope)") ||
                  s.includes(".editor-stacks-scope")
                ) {
                  return s;
                }
                return `:where(.editor-stacks-scope) ${s}`;
              });

              rule.selectors = scopedSelectors;
            });
          },
        },
      ],
    },
  },
});
