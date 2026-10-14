import express from 'express'; import cors from 'cors'; import helmet from 'helmet'; import rateLimit from 'express-rate-limit';
import { createClient } from '@supabase/supabase-js';
import { runScan, computeStats } from './scan.js'; import { store as realStore } from './store.js'; import { providerStatus } from './providers.js';
const UUID = /^[0-9a-f-]{36}$/i, STATUSES = ['new','investigating','resolved','dismissed'];
export const realAuth = (env) => async (token) => {
  const client = createClient(env.SUPABASE_URL, env.SUPABASE_PUBLISHABLE_KEY, { global:{ headers:{ Authorization:'Bearer '+token } }, auth:{ persistSession:false } });
  const { data, error } = await client.auth.getUser(token); if (error || !data?.user) throw new Error('unauthorized');
  return { user:data.user, client };
};
export function createApp({ env=process.env, deps={} } = {}) {
  const f = deps.fetch || fetch, store = deps.store || realStore, authenticate = deps.authenticate || realAuth(env);
  const origins = (env.FRONTEND_ORIGIN || 'http://localhost:3000').split(',').map(s => s.trim()).filter(Boolean);
  const app = express(); app.disable('x-powered-by'); app.set('trust proxy', 1);
  app.use(helmet()); app.use(cors({ origin:(o, cb) => cb(null, !o || origins.includes(o)), methods:['GET','POST','PATCH','DELETE'] }));
  app.use(express.json({ limit:'10kb' })); app.use('/api', rateLimit({ windowMs:60000, limit:120, standardHeaders:true, legacyHeaders:false }));
  const scanLimit = rateLimit({ windowMs:60000, limit:10, message:{ error:'Too many scans. Wait a minute and try again.' } });
  app.get('/api/health', (q, r) => r.json({ ok:true }));
  app.get('/api/providers/status', (q, r) => r.json(providerStatus(env)));
  const need = async (req, res, next) => { const t = (req.headers.authorization||'').replace(/^Bearer /i,'');
    if (!t) return res.status(401).json({ error:'Sign in to continue.' });
    try { req.auth = await authenticate(t); next(); } catch { res.status(401).json({ error:'Your session has expired. Sign in again.' }); } };
  const wrap = (fn) => async (req, res) => { try { await fn(req, res); } catch (e) {
    if (e.status === 400) return res.status(400).json({ error:e.message });
    console.error('request failed:', e.code || e.name); res.status(500).json({ error:'Something went wrong. Please try again.' }); } };
  app.post('/api/scans', scanLimit, need, wrap(async (req, res) => { // user_id is never read from the body; the DB defaults it to auth.uid()
    const row = await runScan(req.body, env, f); res.status(201).json(await store.createScan(req.auth.client, row)); }));
  app.get('/api/scans', need, wrap(async (req, res) => res.json(await store.listScans(req.auth.client))));
  app.get('/api/scans/:id', need, wrap(async (req, res) => { if (!UUID.test(req.params.id)) return res.status(400).json({ error:'Invalid id.' });
    const s = await store.getScan(req.auth.client, req.params.id); s ? res.json(s) : res.status(404).json({ error:'Not found.' }); }));
  app.delete('/api/scans/:id', need, wrap(async (req, res) => { if (!UUID.test(req.params.id)) return res.status(400).json({ error:'Invalid id.' });
    await store.deleteScan(req.auth.client, req.params.id); res.json({ ok:true }); }));
  app.get('/api/dashboard/stats', need, wrap(async (req, res) => res.json(computeStats(await store.listScans(req.auth.client)))));
  app.patch('/api/investigations/:id', need, wrap(async (req, res) => { if (!UUID.test(req.params.id) || !STATUSES.includes(req.body?.status)) return res.status(400).json({ error:'Invalid status.' });
    const r = await store.setStatus(req.auth.client, req.params.id, req.body.status); r ? res.json(r) : res.status(404).json({ error:'Not found.' }); }));
  app.post('/api/investigations/:id/notes', need, wrap(async (req, res) => { const n = typeof req.body?.note==='string' ? req.body.note.trim() : '';
    if (!UUID.test(req.params.id) || !n || n.length > 1000) return res.status(400).json({ error:'Write a note of up to 1000 characters.' });
    const r = await store.addNote(req.auth.client, req.params.id, n); r ? res.json(r) : res.status(404).json({ error:'Not found.' }); }));
  app.use((q, r) => r.status(404).json({ error:'Not found.' }));
  return app;
}
