/** @type {import('next').NextConfig} */
const nextConfig = {
  transpilePackages: ["@sun-security/core"],
  poweredByHeader: false,
  reactStrictMode: true,
};
export default nextConfig;
