export function getClientIp(req: any): string {
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd.length > 0) return fwd.split(',')[0].trim();
  return req.ip || 'unknown';
}

export async function lookupGeo(ip: string): Promise<{ city: string | null; country: string | null }> {
  if (!ip || ip === 'unknown' || ip.startsWith('127.') || ip.startsWith('::1')) {
    return { city: null, country: null };
  }
  try {
    const res = await fetch(`https://ipapi.co/${ip}/json/`);
    if (!res.ok) return { city: null, country: null };
    const data = await res.json();
    return { city: data.city || null, country: data.country_name || null };
  } catch {
    return { city: null, country: null };
  }
}
