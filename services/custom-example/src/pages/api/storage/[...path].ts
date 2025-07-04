import type { NextApiRequest, NextApiResponse } from 'next';

// In-memory storage on the server
// In production, you'd use a proper database
const serverStorage = new Map<string, any>();

type UserData = {
  passkeys?: {
    passkeyId?: string;
  };
  publicKeys?: Record<string, { x: string; y: string }>;
};

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const { method, body } = req;
  const { path } = req.query as { path: string[] };

  console.log('Storage API request:', method, path);

  try {
    // Parse the path: /users/{userId}/passkeys, /users/{userId}/public-keys, etc.
    if (!path || path.length < 2 || path[0] !== 'users') {
      return res.status(400).json({ error: 'Invalid path. Expected /users/{userId}/...' });
    }

    const userId = path[1];
    const endpoint = path[2]; // passkeys, public-keys
    const subPath = path[3]; // for public-keys/{idHash}

    // Get user's storage object
    const userKey = `user:${userId}`;
    const userData: UserData = serverStorage.get(userKey) || {};

    // Handle passkey endpoints: /users/{userId}/passkeys
    if (endpoint === 'passkeys') {
      switch (method) {
        case 'GET':
          res.status(200).json(userData.passkeys || {});
          break;

        case 'PUT':
          if (!userData.passkeys) userData.passkeys = {};

          if (body.passkeyId !== undefined) {
            userData.passkeys.passkeyId = body.passkeyId;
          }

          serverStorage.set(userKey, userData);
          console.log(`✅ Updated passkeys for user ${userId}:`, userData.passkeys);
          res.status(200).json({ success: true });
          break;

        case 'DELETE':
          userData.passkeys = {};
          serverStorage.set(userKey, userData);
          console.log(`🗑️ Cleared passkeys for user ${userId}`);
          res.status(200).json({ success: true });
          break;

        default:
          res.setHeader('Allow', ['GET', 'PUT', 'DELETE']);
          res.status(405).end(`Method ${method} Not Allowed`);
      }
    }

    // Handle public key endpoints: /users/{userId}/public-keys/{idHash}
    else if (endpoint === 'public-keys' && subPath) {
      const idHash = subPath;

      switch (method) {
        case 'GET':
          if (!userData.publicKeys) userData.publicKeys = {};
          const publicKey = userData.publicKeys[idHash];
          res.status(200).json({ publicKey: publicKey || null });
          break;

        case 'PUT':
          if (!userData.publicKeys) userData.publicKeys = {};

          if (body.publicKey) {
            userData.publicKeys[idHash] = body.publicKey;
          }

          serverStorage.set(userKey, userData);
          console.log(`✅ Updated public key for user ${userId}, hash ${idHash}:`, body.publicKey);
          res.status(200).json({ success: true });
          break;

        case 'DELETE':
          if (userData.publicKeys) {
            delete userData.publicKeys[idHash];
            serverStorage.set(userKey, userData);
          }
          console.log(`🗑️ Deleted public key for user ${userId}, hash ${idHash}`);
          res.status(200).json({ success: true });
          break;

        default:
          res.setHeader('Allow', ['GET', 'PUT', 'DELETE']);
          res.status(405).end(`Method ${method} Not Allowed`);
      }
    }

    // Handle getting all public keys: /users/{userId}/public-keys
    else if (endpoint === 'public-keys' && !subPath) {
      switch (method) {
        case 'GET':
          res.status(200).json({ publicKeys: userData.publicKeys || {} });
          break;

        case 'DELETE':
          userData.publicKeys = {};
          serverStorage.set(userKey, userData);
          console.log(`🗑️ Cleared all public keys for user ${userId}`);
          res.status(200).json({ success: true });
          break;

        default:
          res.setHeader('Allow', ['GET', 'DELETE']);
          res.status(405).end(`Method ${method} Not Allowed`);
      }
    }

    // Special endpoint for demo: get all user data
    else if (endpoint === 'all') {
      res.status(200).json({ data: userData });
    } else {
      res.status(404).json({ error: `Unknown endpoint: ${endpoint}` });
    }
  } catch (error) {
    console.error('Storage API error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}