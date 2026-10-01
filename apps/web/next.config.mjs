/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,

  // Workspace packages are consumed as compiled output from `dist`, but listing
  // them here lets Next transpile them too and keeps source maps readable.
  transpilePackages: ['@syscanner/ui', '@syscanner/contracts'],

  // Security headers are set here as a floor; the edge (CDN/WAF) owns the full policy.
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
        ],
      },
    ];
  },

  eslint: {
    // Linting is a separate concern (see README: quality gates).
    ignoreDuringBuilds: true,
  },
};

export default nextConfig;
