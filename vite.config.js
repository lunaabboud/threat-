import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Replace 'threat-intel-pipeline' with your repository name
export default defineConfig({
  plugins: [react()],
  base: '/threat-intel-pipeline/', // Set this to your repo name for GitHub Pages
});
