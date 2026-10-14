import net from 'node:net';
export class InputError extends Error { constructor(m){ super(m); this.status = 400; } }
const BAD_HOST = /(^|\.)(localhost|local|internal|localdomain|home|lan)$/i;
export function isPrivateIp(ip) {
  if (net.isIPv4(ip)) { const [a,b] = ip.split('.').map(Number);
    return a===0||a===10||a===127||(a===169&&b===254)||(a===172&&b>=16&&b<=31)||(a===192&&b===168)||(a===100&&b>=64&&b<=127)||a>=224; }
  if (net.isIPv6(ip)) { const l = ip.toLowerCase(); return l==='::1'||l==='::'||/^f[cd]/.test(l)||l.startsWith('fe80')||l.startsWith('::ffff:'); }
  return false;
}
// Used for reputation lookups only. The server never fetches submitted URLs.
export function normalizeUrl(input) {
  let s = String(input ?? '').trim();
  if (!s || s.length > 200) throw new InputError('Enter a URL of up to 200 characters.');
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'https://' + s;
  let u; try { u = new URL(s); } catch { throw new InputError('That does not look like a valid URL.'); }
  if (!['http:','https:'].includes(u.protocol)) throw new InputError('Only http and https URLs are supported.');
  if (u.username || u.password) throw new InputError('URLs containing a username or password are not accepted.');
  const h = u.hostname.replace(/^\[|\]$/g, '');
  if (BAD_HOST.test(h) || isPrivateIp(h)) throw new InputError('Private, local and internal addresses are not accepted.');
  if (!h.includes('.') && !net.isIP(h)) throw new InputError('Enter a full domain name, such as example.com.');
  u.hash = ''; return u.href;
}
const PLATFORMS = { 'x.com':'X','twitter.com':'X','instagram.com':'Instagram','facebook.com':'Facebook','linkedin.com':'LinkedIn','tiktok.com':'TikTok','youtube.com':'YouTube','t.me':'Telegram','github.com':'GitHub' };
export function platformOf(url) { const h = new URL(url).hostname.replace(/^www\./,''); return PLATFORMS[h] || null; }
