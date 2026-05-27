import { Router, Request, Response } from 'express';
import { executeStaticCodeAnalysis } from './codeAnalyzer.service';
import { prisma } from '../../config/db';

export const analyzerRouter = Router();
analyzerRouter.post('/scan', async (req: Request, res: Response) => {
  try {
    let { projectId, codeSnippet, language } = req.body;
    if (!codeSnippet) return res.status(400).json({ error: 'Source code content context is required.' });

    // If no projectId is passed, automatically use or create a default test project
    if (!projectId) {
      const defaultProject = await prisma.project.findFirst({ where: { name: 'Default Test Project' } }) || 
                             await prisma.project.create({ data: { name: 'Default Test Project' } });
      projectId = defaultProject.id;
    }

    const scan = await prisma.scan.create({ data: { projectId, scanType: 'AI_CODE', status: 'PROCESSING' } });
    const reportSummary = await executeStaticCodeAnalysis(codeSnippet, language);
    await prisma.$transaction(async (tx) => {
      if (reportSummary.findings.length > 0) {
        await tx.finding.createMany({ data: reportSummary.findings.map((f: any) => ({ ...f, scanId: scan.id })) });
      }
      await tx.scan.update({ where: { id: scan.id }, data: { status: 'COMPLETED', securityScore: reportSummary.securityScore } });
    });
    res.status(200).json({ message: 'AI Evaluation Complete.', scanId: scan.id, securityScore: reportSummary.securityScore });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});
