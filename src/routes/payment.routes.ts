import { Router } from 'express';

const router = Router();

router.post('/', async (req, res) => {
  try {
    const { cardNumber = '' } = req.body;

    const clean = cardNumber.replace(/\s|-/g, '');

    // Basic Luhn check
    function luhn(num: string): boolean {
      let sum = 0;
      let alt = false;
      for (let i = num.length - 1; i >= 0; i--) {
        let n = parseInt(num[i], 10);
        if (alt) { n *= 2; if (n > 9) n -= 9; }
        sum += n;
        alt = !alt;
      }
      return sum % 10 === 0;
    }

    const isValid = clean.length >= 13 && clean.length <= 19 && /^\d+$/.test(clean) && luhn(clean);

    let cardType = 'Unknown';
    if (/^4/.test(clean)) cardType = 'VISA';
    else if (/^5[1-5]/.test(clean)) cardType = 'Mastercard';
    else if (/^3[47]/.test(clean)) cardType = 'Amex';
    else if (/^6/.test(clean)) cardType = 'Discover';

    const riskScore = isValid ? 10 : 65;

    res.json({
      success: true,
      environment: 'SANDBOX',
      gateway: 'Cyber-Zero Payment Lab',
      cardType,
      validation: isValid ? 'PASSED' : 'FAILED',
      riskScore,
      findings: [
        { title: 'Card Format', value: isValid ? 'Valid Luhn checksum' : 'Invalid card number' },
        { title: 'Card Type', value: cardType },
        { title: 'Gateway Status', value: 'Operational (Sandbox)' },
        { title: 'Risk Score', value: `${riskScore}/100` },
      ],
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Payment analysis failed' });
  }
});

export default router;
