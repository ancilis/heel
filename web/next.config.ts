import type { NextConfig } from "next";
import path from "path";
// Static export: `npm run build` emits a fully static site in web/out/ (deploy to any static host).
// The control room is a client component reading /data/snapshot.json, so SSR isn't needed.
const nextConfig: NextConfig = {
  output: "export",
  images: { unoptimized: true },
  turbopack: { root: path.join(__dirname) },
};
export default nextConfig;
