import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// During development the console proxies API and WebSocket traffic to the
// gatehouse binary; in production the binary serves console/dist directly.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8080",
      "/stream": { target: "ws://127.0.0.1:8080", ws: true },
    },
  },
});
