import { Router, Request, Response } from 'express';
import Groq from 'groq-sdk';
import { executeStaticCodeAnalysis } from '../analyzer/codeAnalyzer.service';

export const assistantV2Router = Router();

const groq = new Groq({
  apiKey: process.env.GROQ_API_KEY || ''
});

function detectIntent(message: string) {
  const text = message.toLowerCase();

  if (
    text.includes('analyze this code') ||
    text.includes('review this code') ||
    text.includes('code review') ||
    text.includes('vulnerability in code')
  ) {
    return 'CODE_ANALYSIS';
  }

  if (
    text.includes('scan website') ||
    text.includes('scan url') ||
    text.includes('security scan')
  ) {
    return 'WEB_SCAN';
  }

  return 'CHAT';
}

assistantV2Router.post('/chat', async (req: Request, res: Response) => {
  try {
    const {
      message,
      history = [],
      language = 'javascript'
    } = req.body;

    if (!message) {
      return res.status(400).json({
        error: 'Message is required.'
      });
    }

    const intent = detectIntent(message);

    if (intent === 'CODE_ANALYSIS') {
      const report = await executeStaticCodeAnalysis(
        message,
        language
      );

      return res.status(200).json({
        type: 'CODE_ANALYSIS',
        report
      });
    }

    const trimmedHistory = history.slice(-20);

    const response =
      await groq.chat.completions.create({
        model: 'llama-3.3-70b-versatile',
        temperature: 0.7,
        messages: [
          {
            role: 'system',
            content: `
You are Cyber-Zero V2.

You are an elite cybersecurity,
software engineering,
technology intelligence,
API security,
and secure coding assistant.

Always:
- Think step by step
- Be accurate
- Give practical examples
- Prioritize security
- Explain findings clearly
`
          },
          ...trimmedHistory,
          {
            role: 'user',
            content: message
          }
        ]
      });

    return res.status(200).json({
      type: 'CHAT',
      reply:
        response.choices[0]?.message?.content ||
        'No response generated.'
    });

  } catch (err: any) {
    return res.status(500).json({
      error: err.message
    });
  }
});
