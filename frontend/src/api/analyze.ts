import axios from 'axios';
import { AnalysisResult } from '../types';

export async function analyzeContract(source: string): Promise<AnalysisResult> {
  const { data } = await axios.post<AnalysisResult>('/api/analyze', { source });
  return data;
}
