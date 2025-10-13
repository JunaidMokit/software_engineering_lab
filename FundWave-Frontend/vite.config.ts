import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@mui/material': '@mui/material/esm/index.js', // Ensure MUI resolves correctly
      '@mui/icons-material': '@mui/icons-material/esm/index.js',
    },
  },
});
