import { NextApiRequest, NextApiResponse } from 'next';
import { createProxyMiddleware } from 'http-proxy-middleware';
import { config as envConfig } from '../../../config';

// Create the proxy middleware
const hardhatProxy = createProxyMiddleware({
  target: new URL(envConfig.hardhatRpcUrl).origin,
  changeOrigin: true,
  pathRewrite: {
    '^/api/proxy/hardhat': new URL(envConfig.hardhatRpcUrl).pathname, // Remove the proxy path prefix
  },
  onProxyReq: (proxyReq, req, res) => {
    // Log proxy requests for debugging
    console.log(`[Hardhat Proxy] ${req.method} ${req.url} -> http://localhost:8545`);
  },
  onError: (err, req, res) => {
    console.error('[Hardhat Proxy] Error:', err.message);
    res.status(500).json({ error: 'Hardhat proxy error', message: err.message });
  },
});

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  // Disable Next.js body parsing for proxy
  return hardhatProxy(req, res, (result) => {
    if (result instanceof Error) {
      throw result;
    }
  });
}

export const config = {
  api: {
    bodyParser: false, // Disable body parsing for proxy
  },
};