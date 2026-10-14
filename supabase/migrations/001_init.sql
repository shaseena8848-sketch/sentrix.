-- Sentrix AI schema. Paste into Supabase > SQL Editor > Run.
create table public.profiles(
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text check (char_length(display_name)<=80),
  created_at timestamptz not null default now(), updated_at timestamptz not null default now());
create table public.scans(
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  asset_type text not null check (asset_type in ('social','url','app')),
  asset_value text not null check (char_length(asset_value) between 3 and 200),
  risk_score int not null check (risk_score between 0 and 100),
  risk_level text not null check (risk_level in ('low','medium','high')),
  summary text, indicators jsonb not null default '[]', recommendations jsonb not null default '[]',
  analysis_source text not null default 'demo-rules', analysis_status text not null default 'simulated',
  created_at timestamptz not null default now());
create table public.investigations(
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  scan_id uuid not null references public.scans(id) on delete cascade,
  status text not null default 'new' check (status in ('new','investigating','resolved','dismissed')),
  notes text check (char_length(notes)<=5000),
  created_at timestamptz not null default now(), updated_at timestamptz not null default now());
create index on public.scans(user_id, created_at desc);
create index on public.scans(user_id, asset_type, risk_level);
create index on public.investigations(user_id, status);
create index on public.investigations(scan_id);

create function public.touch() returns trigger language plpgsql as $$
begin new.updated_at=now(); return new; end $$;
create trigger t1 before update on public.profiles for each row execute function public.touch();
create trigger t2 before update on public.investigations for each row execute function public.touch();

-- owner and scan link can never change
create function public.lock_owner() returns trigger language plpgsql as $$
begin
  if new.user_id is distinct from old.user_id then raise exception 'owner cannot change'; end if;
  if tg_table_name='investigations' and new.scan_id is distinct from old.scan_id then raise exception 'scan cannot change'; end if;
  return new; end $$;
create trigger l1 before update on public.scans for each row execute function public.lock_owner();
create trigger l2 before update on public.investigations for each row execute function public.lock_owner();

create function public.new_user() returns trigger language plpgsql security definer set search_path='' as $$
begin insert into public.profiles(id,display_name) values(new.id,coalesce(new.raw_user_meta_data->>'display_name',split_part(new.email,'@',1))); return new; end $$;
create trigger on_signup after insert on auth.users for each row execute function public.new_user();

alter table public.profiles enable row level security;
alter table public.scans enable row level security;
alter table public.investigations enable row level security;

create policy p_sel on public.profiles for select to authenticated using (id=(select auth.uid()));
create policy p_upd on public.profiles for update to authenticated using (id=(select auth.uid())) with check (id=(select auth.uid()));
create policy s_sel on public.scans for select to authenticated using (user_id=(select auth.uid()));
create policy s_ins on public.scans for insert to authenticated with check (user_id=(select auth.uid()));
create policy s_del on public.scans for delete to authenticated using (user_id=(select auth.uid()));
create policy i_sel on public.investigations for select to authenticated using (user_id=(select auth.uid()));
create policy i_ins on public.investigations for insert to authenticated with check (user_id=(select auth.uid()) and exists(select 1 from public.scans s where s.id=scan_id and s.user_id=(select auth.uid())));
create policy i_upd on public.investigations for update to authenticated using (user_id=(select auth.uid())) with check (user_id=(select auth.uid()));
create policy i_del on public.investigations for delete to authenticated using (user_id=(select auth.uid()));

revoke all on public.profiles, public.scans, public.investigations from anon;
grant select,update on public.profiles to authenticated;
grant select,insert,delete on public.scans to authenticated;
grant select,insert,update,delete on public.investigations to authenticated;
