import type { NextApiRequest, NextApiResponse } from 'next';

// This is the main storage API router
// It handles routing to specific endpoints based on the URL path
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  // This is just the main /api/storage endpoint
  // The actual routing is handled by the [...path].ts file
  res.status(404).json({ error: 'Use specific storage endpoints like /api/storage/users/{userId}/session' });
}