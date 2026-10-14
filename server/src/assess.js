export const LEVELS = ['low','medium','high','critical'];
const levelOf = (s) => s>=75 ? 'critical' : s>=55 ? 'high' : s>=35 ? 'medium' : 'low';
const RISKY_TLD = /\.(xyz|top|click|zip|buzz|work|icu|cfd)$/i;
const URGENT = /(login|verify|secure|support|helpdesk|giveaway|free|claim|wallet|urgent|suspend|official)/i;
// Transparent deterministic scoring. Provider matches drive the score; text heuristics alone can never exceed 54.
export function assess({ providers, host, brand, text, kind }) {
  const ind = [], basis = []; let score = 5;
  const ran = providers.filter(p => p.ran), matched = ran.filter(p => p.match);
  for (const p of matched) ind.push({ text:`${p.provider} returned a match: ${p.evidence.join('; ')}`, source:'provider' });
  for (const p of ran.filter(p => !p.match && p.suspicious>0)) ind.push({ text:`${p.provider} reports ${p.suspicious} suspicious verdict(s)`, source:'provider' });
  let h = 0; const b = (brand||'').toLowerCase().trim(), hn = (host||'').toLowerCase();
  const add = (n,t) => { h += n; ind.push({ text:t, source:'heuristic' }); };
  if (hn) {
    if (hn.includes('xn--')) add(10,'Hostname uses punycode (can hide lookalike characters)');
    if (/^\d+\.\d+\.\d+\.\d+$/.test(hn)) add(10,'Hostname is a raw IP address');
    if ((hn.match(/-/g)||[]).length>=2) add(8,'Hostname contains several hyphens');
    if (RISKY_TLD.test(hn)) add(8,'Domain suffix is frequently used for low-cost registrations');
    if (b && hn.includes(b) && hn.split('.').length>2) add(10,'Protected brand name appears inside a longer hostname');
  }
  const joined = `${hn} ${text||''}`;
  if (URGENT.test(joined)) add(10,'Trust or urgency wording in the submitted text or hostname');
  if (b && hn && hn.replace(/[^a-z0-9]/g,'').includes(b.replace(/[^a-z0-9]/g,'')) && /[01]/.test(hn)) add(6,'Digits that can imitate letters near the brand name');
  let limited = ran.length===0;
  if (matched.length) { score = Math.min(95, 75 + 10*(matched.length-1) + Math.min(h,10)); basis.push('Score floor of 75 applied because at least one provider returned a match.'); }
  else { score = Math.min(54, score + h); basis.push(`No provider match. Score comes from ${h} points of text heuristics, capped at 54 because heuristics alone are not proof.`); }
  if (limited) basis.push('LIMITED assessment: no threat-intelligence provider completed a check.');
  const limitations = ['Absence of a provider match does not prove an asset is safe.'];
  if (kind==='social') limitations.push('Account authenticity was not verified. Reputation providers do not verify social identities and no social platform API is connected.');
  if (kind==='app') limitations.push('Name-based analysis is not malware scanning. No app binary was inspected.');
  for (const p of providers.filter(p => !p.ran)) limitations.push(`${p.provider}: ${p.status==='unavailable' ? 'not checked' : 'check failed'} (${p.error})`);
  const recommendations = matched.length
    ? ['Do not interact with the asset.','Preserve screenshots and the URL as evidence.','Report it to the platform or hosting provider and brief your security team.']
    : ['Compare against the official asset manually.','Collect screenshots and URLs as evidence.','Have an analyst review before any report or takedown request.'];
  return { score, level: levelOf(score), limited, indicators: ind, basis, limitations, recommendations };
}
