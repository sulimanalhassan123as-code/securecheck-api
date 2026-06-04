import { Router, Request, Response } from 'express';
import Groq from 'groq-sdk';

export const assistantRouter = Router();

const groq = new Groq({
  apiKey: process.env.GROQ_API_KEY || ''
});

assistantRouter.post('/chat', async (req: Request, res: Response) => {
  try {
    const { message } = req.body;

    if (!message) {
      return res.status(400).json({
        error: 'Message is required.'
      });
    }

    const response = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      messages: [
        {
          role: 'system',
          content:
            'You are Cyber-Zero AI Assistant. Help users with cybersecurity, vulnerabilities, APIs, technology intelligence, code reviews and security best practices.'
        },
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
