/** @type {import('next').NextConfig} */
const nextConfig = {
  transpilePackages: ["@sun-security/core"],
  poweredByHeader: false,
  reactStrictMode: true,
  webpack(config) {
    // The shared ESM package uses NodeNext-compatible `.js` import specifiers
    // in TypeScript sources. Resolve them to TS files during Next compilation.
    config.resolve.extensionAlias = {
      ...config.resolve.extensionAlias,
      ".js": [".ts", ".tsx", ".js"],
    };
    return config;
  },
};
export default nextConfig;
