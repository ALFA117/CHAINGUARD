import type { VercelRequest, VercelResponse } from '@vercel/node';
import { analyzeContract } from './_lib/analyzer';

const MAX_BYTES = 50 * 1024;

export default function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const { source } = req.body as { source?: string };

    if (!source || typeof source !== 'string' || !source.trim()) {
      return res.status(400).json({ error: 'Body must include a non-empty "source" field.' });
    }
    if (Buffer.byteLength(source, 'utf8') > MAX_BYTES) {
      return res.status(413).json({ error: 'Contract source exceeds 50 KB limit.' });
    }

    return res.json(analyzeContract(source));
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Analysis failed.';
    return res.status(422).json({ error: message });
  }
}
