import { normalizeUrl, platformOf, InputError } from './urlsafe.js';
import { runUrlProviders, virusTotalHash } from './providers.js';
import { assess } from './assess.js';
import { explain } from './ai.js';
const str = (v, n) => (typeof v === 'string' ? v.trim().slice(0, n) : '');
export async function runScan(body, env, f=fetch) {
  const type = body?.assetType; if (!['social','url','app'].includes(type)) throw new InputError('Choose an asset type.');
  const value = str(body.value, 200); if (value.length < 3) throw new InputError('Enter at least 3 characters.');
  const brand = str(body.brand, 80), text = str(body.details, 300);
  let providers = [], host = '', assetValue = value, normalized = null, platform = null;
  if (type === 'app') {
    const sha = text.match(/\b[a-f0-9]{64}\b/i)?.[0], store = text.match(/https?:\/\/\S+/i)?.[0];
    if (store) { normalized = normalizeUrl(store); host = new URL(normalized).hostname; providers.push(...await runUrlProviders(normalized, env, f)); }
    if (sha) providers.push(await virusTotalHash(sha.toLowerCase(), env, f));
  } else {
    normalized = normalizeUrl(value); assetValue = normalized.slice(0, 200); host = new URL(normalized).hostname;
    if (type === 'social') platform = platformOf(normalized);
    providers = await runUrlProviders(normalized, env, f);
  }
  const a = assess({ providers, host, brand, text: type==='app' ? `${value} ${text}` : text, kind: type });
  if (type==='social' && !platform) a.limitations.push('Platform not recognised from the URL.');
  const evidence = providers;
  const ai = await explain({ evidence, assessment: { score:a.score, level:a.level, limited:a.limited, indicators:a.indicators, user_text: text, platform } }, env, f);
  const matched = providers.filter(p => p.match).map(p => p.provider);
  const summary = a.limited ? 'Limited assessment: no threat-intelligence provider completed a check.' : matched.length ? 'Confirmed match from: ' + matched.join(', ') + '.' : 'Providers that ran returned no match. This is not proof the asset is safe.';
  return { asset_type:type, asset_value:assetValue, normalized_url:normalized, risk_score:a.score, risk_level:a.level, summary,
    indicators:a.indicators, recommendations:a.recommendations, evidence, analysis:{ ...ai, basis:a.basis, limitations:[...a.limitations], platform },
    limited:a.limited, details:{ brand, text }, analysis_source: ai.available ? 'providers+ai' : 'providers', analysis_status: a.limited ? 'limited' : 'completed' };
}
export function computeStats(scans) {
  const by = (k, keys) => Object.fromEntries(keys.map(x => [x, scans.filter(s => s[k]===x).length]));
  const days = {}; for (const s of scans) { const d = String(s.created_at).slice(0,10); days[d] = (days[d]||0)+1; }
  return { total:scans.length, byLevel:by('risk_level',['low','medium','high','critical']), byType:by('asset_type',['social','url','app']),
    openInvestigations:scans.filter(s => (s.investigations?.[0]?.status||'new')==='new').length,
    recent:scans.slice(0,5).map(s => ({ id:s.id, asset_value:s.asset_value, risk_level:s.risk_level, created_at:s.created_at })), activity:days };
}
