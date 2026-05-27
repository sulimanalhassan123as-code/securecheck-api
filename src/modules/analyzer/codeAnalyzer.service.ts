import { GoogleGenAI, Type } from '@google/genai';
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || '' });

export async function executeStaticCodeAnalysis(code: string, language: string) {
  const systemInstructions = `You are an elite automated cybersecurity static analysis agent auditing target logic for application flaws. Return data matching the requested JSON output layout rules exactly.`;
  const response = await ai.models.generateContent({
    model: 'gemini-2.5-pro',
    contents: `Language context: ${language}\n\nCode block to analyze:\n${code}`,
    config: {
      systemInstruction: systemInstructions,
      responseMimeType: 'application/json',
      responseSchema: {
        type: Type.OBJECT,
        properties: {
          securityScore: { type: Type.INTEGER },
          findings: {
            type: Type.ARRAY,
            items: {
              type: Type.OBJECT,
              properties: {
                title: { type: Type.STRING },
                severity: { type: Type.STRING },
                confidence: { type: Type.STRING },
                description: { type: Type.STRING },
                riskExplanation: { type: Type.STRING },
                attackScenario: { type: Type.STRING },
                affectedComponent: { type: Type.STRING },
                lineNumber: { type: Type.INTEGER },
                recommendation: { type: Type.STRING },
                secureCodeExample: { type: Type.STRING },
                checklistSteps: { type: Type.ARRAY, items: { type: Type.STRING } }
              },
              required: ['title', 'severity', 'description', 'riskExplanation', 'recommendation', 'secureCodeExample']
            }
          }
        },
        required: ['securityScore', 'findings']
      }
    }
  });
  const parsedText = response.text;
  if (!parsedText) throw new Error('Empty verification response from AI pipeline.');
  return JSON.parse(parsedText);
}
