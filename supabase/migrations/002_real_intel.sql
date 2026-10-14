-- Run AFTER 001_init.sql. Adds evidence/analysis storage and a 'critical' level. RLS from 001 still applies.
alter table public.scans drop constraint if exists scans_risk_level_check;
alter table public.scans add constraint scans_risk_level_check check (risk_level in ('low','medium','high','critical'));
alter table public.scans add column if not exists normalized_url text;
alter table public.scans add column if not exists evidence jsonb not null default '[]';   -- raw provider results (facts)
alter table public.scans add column if not exists analysis jsonb;                          -- AI interpretation, stored separately
alter table public.scans add column if not exists limited boolean not null default false;  -- true when no provider actually ran
alter table public.scans add column if not exists details jsonb not null default '{}';
