import type { NextConfig } from "next"

const nextConfig: NextConfig = {
  poweredByHeader: false,
  transpilePackages: ["@cipher/ui", "@cipher/db"],
}

export default nextConfig
