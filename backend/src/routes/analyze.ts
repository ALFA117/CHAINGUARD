import { Router, Request, Response } from 'express';
import { analyzeContract } from '../analyzer';

const router = Router();

const MAX_SOURCE_BYTES = 50 * 1024; // 50 KB

router.post('/', (req: Request, res: Response) => {
  const { source } = req.body as { source?: string };

  if (!source || typeof source !== 'string' || source.trim().length === 0) {
    res.status(400).json({ error: 'Request body must include a non-empty "source" field.' });
    return;
  }

  if (Buffer.byteLength(source, 'utf8') > MAX_SOURCE_BYTES) {
    res.status(413).json({ error: 'Contract source exceeds the 50 KB limit.' });
    return;
  }

  try {
    const result = analyzeContract(source);
    res.json(result);
  } catch (err: any) {
    const message = err?.message ?? 'Analysis failed due to an unexpected error.';
    res.status(422).json({ error: message });
  }
});

export default router;
