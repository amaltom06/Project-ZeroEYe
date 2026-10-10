import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
export default defineConfig({
  plugins: [react(),tailwindcss()],
  build:{rolldownOptions:{output:{manualChunks(id){
    const path=id.replaceAll('\\','/');
    if(path.includes('/recharts/'))return 'charts';
    if(path.includes('/@tanstack/'))return 'query';
    if(/\/node_modules\/(?:react|react-dom|react-router|react-router-dom)\//.test(path))return 'react';
  }}}},
  server:{proxy:{'/api':{target:'http://127.0.0.1:4000',ws:true}}}
});
