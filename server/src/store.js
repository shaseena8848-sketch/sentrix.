// All access uses the signed-in user's own Supabase client, so Row Level Security applies. No service-role key.
const must = ({ data, error }) => { if (error) throw error; return data; };
export const store = {
  async createScan(c, row) { const scan = must(await c.from('scans').insert(row).select().single());
    const inv = must(await c.from('investigations').insert({ scan_id: scan.id }).select().single()); return { ...scan, investigations:[inv] }; },
  async listScans(c) { return must(await c.from('scans').select('*,investigations(id,status,notes)').order('created_at',{ascending:false}).limit(200)); },
  async getScan(c, id) { return must(await c.from('scans').select('*,investigations(id,status,notes)').eq('id',id).maybeSingle()); },
  async setStatus(c, id, status) { return must(await c.from('investigations').update({status}).eq('id',id).select().maybeSingle()); },
  async addNote(c, id, note) { const cur = must(await c.from('investigations').select('notes').eq('id',id).maybeSingle()); if (!cur) return null;
    return must(await c.from('investigations').update({ notes:((cur.notes||'')+'\n'+note).trim().slice(0,5000) }).eq('id',id).select().maybeSingle()); },
  async deleteScan(c, id) { must(await c.from('scans').delete().eq('id',id)); }
};
