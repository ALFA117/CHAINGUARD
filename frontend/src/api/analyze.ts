import axios from 'axios';
import { AnalysisResult } from '../types';

const VERCEL_API = (import.meta.env.VITE_API_URL as string | undefined) ?? '/api';
const SUPABASE_URL = import.meta.env.VITE_SUPABASE_FUNCTION_URL as string | undefined;
const SUPABASE_KEY = import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined;

export async function analyzeContract(source: string): Promise<AnalysisResult> {
  // Primary: Vercel API Route (same domain, full AST analysis, no CORS)
  try {
    const { data } = await axios.post<AnalysisResult>(`${VERCEL_API}/analyze`, { source });
    return data;
  } catch (primaryErr) {
    // Fallback: Supabase Edge Function
    if (SUPABASE_URL) {
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (SUPABASE_KEY) headers['apikey'] = SUPABASE_KEY;

      const { data } = await axios.post<AnalysisResult>(SUPABASE_URL, { source }, { headers });
      return data;
    }
    throw primaryErr;
  }
}
