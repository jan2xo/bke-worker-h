import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import {defineConfig} from 'vite';

export default defineConfig(() => {
  return {
    plugins: [
      react(),
      tailwindcss(),
      {
        name: 'patch-attachment-headers',
        configureServer(server) {
          server.middlewares.use('/bke-worker-f1-completion.patch', (_req, res, next) => {
            res.setHeader('Content-Type', 'text/x-patch; charset=utf-8');
            res.setHeader(
              'Content-Disposition',
              'attachment; filename="bke-worker-f1-completion.patch"',
            );
            next();
          });
        },
      },
    ],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    server: {
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modify—file watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      // Disable file watching when DISABLE_HMR is true to save CPU during agent edits.
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
