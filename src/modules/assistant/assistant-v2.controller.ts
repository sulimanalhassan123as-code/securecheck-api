import { Router, Request, Response } from 'express';
import Groq from 'groq-sdk';
import { Queue } from 'bullmq';
import { redisConnection } from '../../config/redis';
import { prisma } from '../../config/db';
import { executeStaticCodeAnalysis } from '../analyzer/codeAnalyzer.service';

export const assistantV2Router = Router();

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY || '' });

const webScanQueue = new Queue('web-header-audit-queue', { connection: redisConnection });

function detectIntent(message: string): 'CODE_ANALYSIS' | 'WEB_SCAN' | 'CHAT' {
  const text = message.toLowerCase().trim();

  const codeIndicators = [
    'analyze this code', 'review this code', 'code review',
    'vulnerability in code', 'const ', 'let ', 'var ',
    'function ', 'class ', 'password', 'apikey', 'api key',
    'secret', 'token', 'jwt', 'bearer', 'select ', 'insert ',
    'update ', 'delete ', 'fetch(', 'axios(', '<?php',
    'public static void main', 'def ',
  ];

  if (codeIndicators.some(k => text.includes(k))) return 'CODE_ANALYSIS';

  if (
    text.startsWith('http://') ||
    text.startsWith('https://') ||
    text.includes('scan website') ||
    text.includes('scan url') ||
    text.includes('security scan')
  ) return 'WEB_SCAN';

  return 'CHAT';
}

assistantV2Router.post('/chat', async (req: Request, res: Response) => {
  try {
    const { message, history = [], language = 'javascript' } = req.body;

    if (!message) return res.status(400).json({ error: 'Message is required.' });

    const intent = detectIntent(message);

    // ── CODE ANALYSIS ──
    if (intent === 'CODE_ANALYSIS') {
      const report = await executeStaticCodeAnalysis(message, language);
      return res.status(200).json({ type: 'CODE_ANALYSIS', report });
    }

    // ── WEB SCAN ──
    if (intent === 'WEB_SCAN') {
      const defaultProject =
        await prisma.project.findFirst({ where: { name: 'Default Test Project' } }) ||
        await prisma.project.create({ data: { name: 'Default Test Project' } });

      const scan = await prisma.scan.create({
        data: {
          projectId: defaultProject.id,
          targetUrl: message.trim(),
          scanType: 'WEB_HEADERS',
          status: 'QUEUED',
        },
      });

      await webScanQueue.add('analyze-headers', { scanId: scan.id, targetUrl: message.trim() });

      return res.status(200).json({ type: 'WEB_SCAN', message: 'Scan queued successfully', scanId: scan.id });
    }

    // ── CHAT ──
    const trimmedHistory = (history as { role: string; content: string }[]).slice(-20);

    const response = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      temperature: 0.7,
      messages: [
        {
          role: 'system',
          content: `You are Cyber-Zero V2 — an elite cybersecurity, software engineering, technology intelligence, API security, secure coding, and vulnerability assessment assistant.

Always:
- Think step by step
- Be accurate and concise
- Give practical, actionable examples
- Prioritize security best practices
- Explain findings clearly
- Recommend secure alternatives when applicable
- Keep responses well-structured and readable`,
        },
        ...trimmedHistory.map(h => ({ role: h.role as 'user' | 'assistant', content: h.content })),
        { role: 'user', content: message },
      ],
    });

    return res.status(200).json({
      type: 'CHAT',
      reply: response.choices[0]?.message?.content || 'No response generated.',
    });

  } catch (err: any) {
    console.error('AssistantV2 error:', err.message);
    return res.status(500).json({ error: err.message });
  }
});
