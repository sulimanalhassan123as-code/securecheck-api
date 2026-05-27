export interface IFindingPayload {
  title: string;
  severity: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: 'LOW' | 'MEDIUM' | 'HIGH';
  description: string;
  riskExplanation: string;
  attackScenario: string;
  affectedComponent: string;
  lineNumber: number;
  recommendation: string;
  secureCodeExample: string;
  checklistSteps: string[];
}
