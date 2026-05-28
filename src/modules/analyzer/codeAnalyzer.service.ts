import Groq from 'groq-sdk';

// Initialize the Groq core interface engine
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY || '' });

export async function executeStaticCodeAnalysis(code: string, language: string) {
  const systemInstructions = `You are an elite automated cybersecurity static analysis agent auditing target logic for application flaws. 
You must respond with a valid JSON object matching this structure exactly:
{
  "securityScore": 85,
  "findings": [
    {
      "title": "String",
      "severity": "String",
      "confidence": "String",
      "description": "String",
      "riskExplanation": "String",
      "attackScenario": "String",
      "affectedComponent": "String",
      "lineNumber": 0,
      "recommendation": "String",
      "secureCodeExample": "String",
      "checklistSteps": ["String"]
    }
  ]
}`;

  // Fire execution call to the high-performance Llama 3.3 engine
  const response = await groq.chat.completions.create({
    model: 'llama-3.3-70b-versatile',
    messages: [
      { role: 'system', content: systemInstructions },
      { role: 'user', content: `Language context: ${language}\n\nCode block to analyze:\n${code}` }
  	],
    response_format: { type: 'json_object' }
  });

  const parsedText = response.choices[0]?.message?.content;
  if (!parsedText) throw new Error('Empty verification response from AI pipeline.');
  
  return JSON.parse(parsedText);
}
