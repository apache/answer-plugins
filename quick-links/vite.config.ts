import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react-swc';
import ViteYaml from '@modyfi/vite-plugin-yaml';
import dts from 'vite-plugin-dts';

import packageJson from './package.json';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    react(),
    ViteYaml(),
    dts({
      insertTypesEntry: true,
    }),
  ],
  build: {
    lib: {
      entry: 'index.ts',
      name: packageJson.name,
      fileName: (format) => `${packageJson.name}.${format}.js`,
    },
    rollupOptions: {
      external: ['react', 'react-dom', 'react-i18next', 'react-bootstrap', 'swr'],
      output: {
        globals: {
          react: 'React',
          'react-dom': 'ReactDOM',
          'react-i18next': 'reactI18next',
          'react-bootstrap': 'reactBootstrap',
          'swr': 'Swr',
        },
      },
    },
  },
});
