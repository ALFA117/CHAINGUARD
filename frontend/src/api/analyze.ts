import axios from 'axios';
import { AnalysisResult } from '../types';

// Primary: Vercel API Route (same domain, no CORS, full AST analysis)
// Fallback: Supabase Edge Function (set VITE_SUPABASE_FUNCTION_URL to enable)
const BASE_URL =
  (import.meta.env.VITE_API_URL as string | undefined) ??
  '/api';

const SUPABASE_URL = import.meta.env.VITE_SUPABASE_FUNCTION_URL as string | undefined;

export async function analyzeContract(source: string): Promise<AnalysisResult> {
  // Try Vercel API route first (preferred)
  try {
    const { data } = await axios.post<AnalysisResult>(`${BASE_URL}/analyze`, { source });
    return data;
  } catch (primaryErr) {
    // Fall back to Supabase Edge Function if configured and primary failed
    if (SUPABASE_URL) {
      const { data } = await axios.post<AnalysisResult>(SUPABASE_URL, { source });
      return data;
    }
    throw primaryErr;
  }
}
