import { NextApiRequest, NextApiResponse } from 'next';
import { createProxyMiddleware } from 'http-proxy-middleware';
import { config as envConfig } from '../../../config';

// Create the proxy middleware
const bundlerProxy = createProxyMiddleware({
  target: new URL(envConfig.bundlerRpcUrl).origin,
  changeOrigin: true,
  pathRewrite: {
    '^/api/proxy/bundler': new URL(envConfig.bundlerRpcUrl).pathname, // Map to the correct bundler path
  },
  onProxyReq: (proxyReq, req, res) => {
    // Log proxy requests for debugging
    console.log(`[Bundler Proxy] ${req.method} ${req.url} -> http://localhost:4337/proxy/rpc`);
  },
  onError: (err, req, res) => {
    console.error('[Bundler Proxy] Error:', err.message);
    res.status(500).json({ error: 'Bundler proxy error', message: err.message });
  },
});

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  // Disable Next.js body parsing for proxy
  return bundlerProxy(req, res, (result) => {
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