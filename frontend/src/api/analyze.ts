import axios from 'axios';
import { AnalysisResult } from '../types';

const BASE_URL = (import.meta.env.VITE_API_URL as string | undefined) ?? '/api';

export async function analyzeContract(source: string): Promise<AnalysisResult> {
  const { data } = await axios.post<AnalysisResult>(`${BASE_URL}/analyze`, { source });
  return data;
}
