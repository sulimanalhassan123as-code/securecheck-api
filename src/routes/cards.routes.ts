import { Router, Request, Response } from 'express';
import { prisma } from '../config/db';

export const cardsRouter = Router();

const ADMIN_KEY = process.env.ADMIN_KEY || '';

function isAdmin(req: Request) {
  return !!ADMIN_KEY && req.header('x-admin-key') === ADMIN_KEY;
}

// GET /api/cards — public. Returns active custom feature cards, ordered.
// The homepage merges these with its built-in modules and renders them
// instantly — no code deploy needed to add a new tile to the site.
cardsRouter.get('/cards', async (req: Request, res: Response) => {
  try {
    const cards = await prisma.featureCard.findMany({
      where: { isActive: true },
      orderBy: { sortOrder: 'asc' },
    });
    res.json({ success: true, cards });
  } catch (err: any) {
    console.error('❌ CARDS FETCH FAILED:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/cards/admin — admin-only. Returns ALL cards including inactive
// ones, for managing them in the admin dashboard.
cardsRouter.get('/cards/admin', async (req: Request, res: Response) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ success: false, error: 'Unauthorized' });
    const cards = await prisma.featureCard.findMany({ orderBy: { sortOrder: 'asc' } });
    res.json({ success: true, cards });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/cards — admin-only. Body: { name, desc, icon, link, bg, accent, sortOrder }.
// Creates a new tile that shows up on the homepage instantly (no deploy).
cardsRouter.post('/cards', async (req: Request, res: Response) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ success: false, error: 'Unauthorized' });
    const { name, desc, icon, link, bg, accent, sortOrder } = req.body;
    if (!name || !link) return res.status(400).json({ success: false, error: 'name and link are required.' });

    const card = await prisma.featureCard.create({
      data: {
        name,
        desc: desc || '',
        icon: icon || '✨',
        link,
        bg: bg || '#4338ca',
        accent: accent || '#a5b4fc',
        sortOrder: typeof sortOrder === 'number' ? sortOrder : 0,
      },
    });
    res.json({ success: true, card });
  } catch (err: any) {
    console.error('❌ CARD CREATE FAILED:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// PATCH /api/cards/:id — admin-only. Partial update (edit fields, toggle isActive, reorder).
cardsRouter.patch('/cards/:id', async (req: Request, res: Response) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ success: false, error: 'Unauthorized' });
    const { name, desc, icon, link, bg, accent, sortOrder, isActive } = req.body;

    const data: any = {};
    if (name !== undefined) data.name = name;
    if (desc !== undefined) data.desc = desc;
    if (icon !== undefined) data.icon = icon;
    if (link !== undefined) data.link = link;
    if (bg !== undefined) data.bg = bg;
    if (accent !== undefined) data.accent = accent;
    if (sortOrder !== undefined) data.sortOrder = sortOrder;
    if (isActive !== undefined) data.isActive = isActive;

    const card = await prisma.featureCard.update({ where: { id: req.params.id }, data });
    res.json({ success: true, card });
  } catch (err: any) {
    console.error('❌ CARD UPDATE FAILED:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// DELETE /api/cards/:id — admin-only.
cardsRouter.delete('/cards/:id', async (req: Request, res: Response) => {
  try {
    if (!isAdmin(req)) return res.status(401).json({ success: false, error: 'Unauthorized' });
    await prisma.featureCard.delete({ where: { id: req.params.id } });
    res.json({ success: true });
  } catch (err: any) {
    console.error('❌ CARD DELETE FAILED:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});
