import { Router } from 'express';
// @ts-ignore
import whois from 'whois-json';

const router = Router();

router.post('/', async (req, res) => {
  try {
    const { domain } = req.body;
    if (!domain) return res.status(400).json({ error: 'Domain is required' });

    const cleanDomain = domain.replace('https://', '').replace('http://', '').split('/')[0];
    const result = await whois(cleanDomain);

    let riskLevel = 'Low';
    if (!result.registrar) riskLevel = 'Medium';
    if (!result.creationDate) riskLevel = 'High';

    res.json({
      success: true,
      domain: cleanDomain,
      riskLevel,
      registrar: result.registrar || result.registrarName || 'Unknown',
      creationDate: result.creationDate || 'Unknown',
      expirationDate: result.registryExpiryDate || result.expirationDate || 'Unknown',
      nameServers: result.nameServer || result.nameServers || [],
    });
  } catch (error) {
    console.error('Domain error:', error);
    res.status(500).json({ success: false, error: 'Domain intelligence failed' });
  }
});

export default router;
