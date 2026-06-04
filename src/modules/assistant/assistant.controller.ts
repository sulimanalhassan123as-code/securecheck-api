import { Router, Request, Response } from 'express';
import Groq from 'groq-sdk';

export const assistantRouter = Router();

const groq = new Groq({
  apiKey: process.env.GROQ_API_KEY || ''
});

assistantRouter.post('/chat', async (req: Request, res: Response) => {
  try {
    const { message, history = [] } = req.body;

    if (!message) {
      return res.status(400).json({
        error: 'Message is required.'
      });
    }

    const response = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      temperature: 0.7,

      messages: [
        {
          role: 'system',
          content: `
You are Cyber-Zero.

You are an elite cybersecurity, software engineering,
technology intelligence and secure coding assistant.

Your responsibilities:

- Analyze source code
- Review vulnerabilities
- Explain security findings
- Generate secure code
- Analyze APIs
- Explain technologies
- Help developers debug applications
- Think step-by-step
- Provide practical examples

Always prioritize security, accuracy and developer productivity.
`
        },

        ...history,

        {
          role: 'user',
          content: message
        }
      ]
    });

    res.status(200).json({
      reply:
        response.choices[0]?.message?.content ||
        'No response generated.'
    });

  } catch (err: any) {
    res.status(500).json({
      error: err.message
    });
  }
});
