// Every provider returns the same shape. ran=true only if a real request succeeded.
const blank = (provider) => ({ provider, ran:false, status:'unavailable', match:false, evidence:[], checkedAt:new Date().toISOString(), error:null });
const fail = (o, e) => { o.status='failed'; o.error = e?.name==='TimeoutError' ? 'The provider request timed out.' : 'The provider request failed.'; return o; };
const sig = () => AbortSignal.timeout(8000);

export async function safeBrowsing(url, env, f=fetch) {
  const o = blank('Google Safe Browsing');
  if (!env.GOOGLE_SAFE_BROWSING_API_KEY) { o.error='API key not configured.'; return o; }
  try {
    const r = await f('https://safebrowsing.googleapis.com/v4/threatMatches:find?key='+encodeURIComponent(env.GOOGLE_SAFE_BROWSING_API_KEY), {
      method:'POST', headers:{'content-type':'application/json'}, signal:sig(),
      body: JSON.stringify({ client:{clientId:'sentrix-ai',clientVersion:'1.0.0'}, threatInfo:{ threatTypes:['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE','POTENTIALLY_HARMFUL_APPLICATION'], platformTypes:['ANY_PLATFORM'], threatEntryTypes:['URL'], threatEntries:[{url}] } }) });
    if (r.status===429) { o.status='failed'; o.error='Quota or rate limit reached.'; return o; }
    if (!r.ok) { o.status='failed'; o.error='Provider returned HTTP '+r.status+'.'; return o; }
    const j = await r.json(); const m = j.matches || [];
    o.ran = true; o.match = m.length>0; o.status = o.match ? 'match' : 'no_match';
    o.evidence = m.map(x => `${x.threatType} (${x.platformType})`);
  } catch (e) { return fail(o, e); }
  return o;
}

const vtBody = async (o, r, what) => {
  if (r.status===404) { o.ran=true; o.status='no_report'; o.evidence=['VirusTotal has no existing report for this '+what+'. No new analysis was requested.']; return o; }
  if (r.status===429) { o.status='failed'; o.error='Quota or rate limit reached (public API is limited).'; return o; }
  if (r.status===401 || r.status===403) { o.status='failed'; o.error='API key rejected.'; return o; }
  if (!r.ok) { o.status='failed'; o.error='Provider returned HTTP '+r.status+'.'; return o; }
  const a = (await r.json())?.data?.attributes;
  const s = a?.last_analysis_stats;
  if (!s) { o.ran=true; o.status='pending'; o.evidence=['A report exists but analysis results are not available yet.']; return o; }
  o.ran=true; o.match = (s.malicious||0) > 0; o.status = o.match ? 'match' : 'no_match';
  const when = a.last_analysis_date ? new Date(a.last_analysis_date*1000).toISOString() : 'unknown date';
  o.evidence = [`Cached report from ${when}`, `malicious ${s.malicious||0}, suspicious ${s.suspicious||0}, harmless ${s.harmless||0}, undetected ${s.undetected||0}`];
  o.suspicious = s.suspicious||0; return o;
};
export async function virusTotalUrl(url, env, f=fetch) {
  const o = blank('VirusTotal');
  if (!env.VIRUSTOTAL_API_KEY) { o.error='API key not configured.'; return o; }
  try { const id = Buffer.from(url).toString('base64url');
    return await vtBody(o, await f('https://www.virustotal.com/api/v3/urls/'+id, { headers:{'x-apikey':env.VIRUSTOTAL_API_KEY}, signal:sig() }), 'URL');
  } catch (e) { return fail(o, e); }
}
export async function virusTotalHash(sha256, env, f=fetch) {
  const o = blank('VirusTotal (file hash)');
  if (!env.VIRUSTOTAL_API_KEY) { o.error='API key not configured.'; return o; }
  try { return await vtBody(o, await f('https://www.virustotal.com/api/v3/files/'+sha256, { headers:{'x-apikey':env.VIRUSTOTAL_API_KEY}, signal:sig() }), 'file hash');
  } catch (e) { return fail(o, e); }
}
export async function urlhaus(url, env, f=fetch) {
  const o = blank('URLhaus');
  if (!env.URLHAUS_API_KEY) { o.error='abuse.ch Auth-Key not configured.'; return o; }
  try {
    const r = await f('https://urlhaus-api.abuse.ch/v1/url/', { method:'POST', headers:{'Auth-Key':env.URLHAUS_API_KEY,'content-type':'application/x-www-form-urlencoded'}, body:new URLSearchParams({url}), signal:sig() });
    if (r.status===401 || r.status===403) { o.status='failed'; o.error='Auth-Key rejected.'; return o; }
    if (!r.ok) { o.status='failed'; o.error='Provider returned HTTP '+r.status+'.'; return o; }
    const j = await r.json();
    if (j.query_status==='ok') { o.ran=true; o.match=true; o.status='match'; o.evidence=[`Listed in URLhaus (status: ${j.url_status||'unknown'}, threat: ${j.threat||'unknown'}, added: ${j.date_added||'unknown'})`]; }
    else if (j.query_status==='no_results') { o.ran=true; o.status='no_match'; }
    else { o.status='failed'; o.error='Unexpected provider response.'; }
  } catch (e) { return fail(o, e); }
  return o;
}
export const runUrlProviders = (url, env, f) => Promise.all([safeBrowsing(url,env,f), virusTotalUrl(url,env,f), urlhaus(url,env,f)]);
export function providerStatus(env) {
  return { googleSafeBrowsing:!!env.GOOGLE_SAFE_BROWSING_API_KEY, virusTotal:!!env.VIRUSTOTAL_API_KEY, urlhaus:!!env.URLHAUS_API_KEY, ai:!!(env.AI_PROVIDER_API_KEY && env.AI_MODEL) };
}
