import type { VercelRequest, VercelResponse } from '@vercel/node';
import { analyzeContract } from './_lib/analyzer';

const MAX_BYTES = 50 * 1024;

export default function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { source } = req.body as { source?: string };

  if (!source || typeof source !== 'string' || source.trim().length === 0) {
    return res.status(400).json({ error: 'Request body must include a non-empty "source" field.' });
  }

  if (Buffer.byteLength(source, 'utf8') > MAX_BYTES) {
    return res.status(413).json({ error: 'Contract source exceeds the 50 KB limit.' });
  }

  try {
    return res.json(analyzeContract(source));
  } catch (err: any) {
    return res.status(422).json({ error: err?.message ?? 'Analysis failed.' });
  }
}
