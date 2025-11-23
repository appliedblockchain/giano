import type { NextApiRequest, NextApiResponse } from 'next';

type WebAuthnConfig = {
  origins: string[];
};

type GlobalWithWebAuthnConfig = {
  __webauthnConfig?: WebAuthnConfig;
};

const globalWithConfig = globalThis as GlobalWithWebAuthnConfig;

// Initialize config - reuse existing if module reloads
if (!globalWithConfig.__webauthnConfig) {
  globalWithConfig.__webauthnConfig = { origins: [] };
  console.log(`[API] Fresh .well-known/webauthn config initialized`);
} else {
  console.log(`[API] Reusing existing .well-known/webauthn config with ${globalWithConfig.__webauthnConfig.origins.length} origins`);
}

const webauthnConfig = globalWithConfig.__webauthnConfig;

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  // Set proper headers for .well-known/webauthn
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (req.method === 'GET') {
    // Return current .well-known configuration
    res.status(200).json(webauthnConfig);
    return;
  }

  if (req.method === 'POST') {
    // Add origin to .well-known configuration
    const { origin } = req.body;

    if (!origin || typeof origin !== 'string') {
      res.status(400).json({ error: 'Origin is required' });
      return;
    }

    try {
      if (!webauthnConfig.origins.includes(origin)) {
        webauthnConfig.origins.push(origin);
        console.log(`[API] Added origin to .well-known config: ${origin}`);
      }
      res.status(200).json(webauthnConfig);
    } catch (error) {
      console.error('[API] Error adding origin:', error);
      res.status(500).json({ error: 'Failed to update configuration' });
    }
    return;
  }

  if (req.method === 'DELETE') {
    // Remove origin from .well-known configuration
    const { origin } = req.body;

    if (!origin || typeof origin !== 'string') {
      res.status(400).json({ error: 'Origin is required' });
      return;
    }

    try {
      const originalLength = webauthnConfig.origins.length;
      webauthnConfig.origins = webauthnConfig.origins.filter((o) => o !== origin);

      if (webauthnConfig.origins.length < originalLength) {
        console.log(`[API] Removed origin from .well-known config: ${origin}`);
      }

      res.status(200).json(webauthnConfig);
    } catch (error) {
      console.error('[API] Error removing origin:', error);
      res.status(500).json({ error: 'Failed to update configuration' });
    }
    return;
  }

  res.setHeader('Allow', ['GET', 'POST', 'DELETE', 'OPTIONS']);
  res.status(405).json({ error: 'Method not allowed' });
} 