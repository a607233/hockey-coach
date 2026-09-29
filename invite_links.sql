create extension if not exists pgcrypto;

create table if not exists public.hc_invite_links (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references public.hc_teams(id) on delete cascade,
  token uuid not null unique default gen_random_uuid(),
  role public.hc_role not null,
  created_by uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '7 days'),
  max_uses integer not null default 50 check (max_uses between 1 and 500),
  use_count integer not null default 0,
  revoked_at timestamptz,
  check (role <> 'OWNER')
);

alter table public.hc_invite_links enable row level security;
revoke all on public.hc_invite_links from anon, authenticated;
grant select on public.hc_invite_links to authenticated;

drop policy if exists hc_invite_links_owner_read on public.hc_invite_links;
create policy hc_invite_links_owner_read on public.hc_invite_links
for select to authenticated
using (private.hc_is_owner(team_id));

create or replace function public.hc_create_invite_link(
  p_team_id uuid,
  p_role public.hc_role,
  p_expires_hours integer default 168,
  p_max_uses integer default 50
) returns table(token uuid, expires_at timestamptz, max_uses integer)
language plpgsql security definer set search_path = '' as $$
declare v public.hc_invite_links%rowtype;
begin
  if auth.uid() is null then raise exception 'LOGIN_REQUIRED'; end if;
  if not private.hc_is_owner(p_team_id) then raise exception 'OWNER_ONLY'; end if;
  if p_role = 'OWNER' then raise exception 'INVALID_ROLE'; end if;
  if p_expires_hours < 1 or p_expires_hours > 720 then raise exception 'INVALID_EXPIRY'; end if;
  if p_max_uses < 1 or p_max_uses > 500 then raise exception 'INVALID_MAX_USES'; end if;

  update public.hc_invite_links
     set revoked_at = now()
   where team_id = p_team_id and role = p_role and revoked_at is null and expires_at > now();

  insert into public.hc_invite_links(team_id, role, created_by, expires_at, max_uses)
  values (p_team_id, p_role, auth.uid(), now() + make_interval(hours => p_expires_hours), p_max_uses)
  returning * into v;

  return query select v.token, v.expires_at, v.max_uses;
end; $$;

create or replace function public.hc_accept_invite_link(p_token uuid)
returns table(team_id uuid, team_name text, role public.hc_role)
language plpgsql security definer set search_path = '' as $$
declare v public.hc_invite_links%rowtype;
declare nm text;
begin
  if auth.uid() is null then raise exception 'LOGIN_REQUIRED'; end if;

  select * into v from public.hc_invite_links
   where token = p_token
   for update;
  if not found then raise exception 'INVITE_NOT_FOUND'; end if;
  if v.revoked_at is not null then raise exception 'INVITE_REVOKED'; end if;
  if v.expires_at <= now() then raise exception 'INVITE_EXPIRED'; end if;
  if v.use_count >= v.max_uses then raise exception 'INVITE_FULL'; end if;

  insert into public.hc_members(team_id,user_id,role,display_name)
  values (v.team_id,auth.uid(),v.role,coalesce((select raw_user_meta_data->>'display_name' from auth.users where id=auth.uid()),''))
  on conflict (team_id,user_id) do nothing;

  if found then
    update public.hc_invite_links set use_count = use_count + 1 where id = v.id;
  end if;

  select t.name into nm from public.hc_teams t where t.id=v.team_id;
  return query select v.team_id,nm,v.role;
end; $$;

create or replace function public.hc_revoke_invite_link(p_token uuid)
returns void language plpgsql security definer set search_path = '' as $$
declare tid uuid;
begin
  select team_id into tid from public.hc_invite_links where token=p_token;
  if tid is null then raise exception 'INVITE_NOT_FOUND'; end if;
  if not private.hc_is_owner(tid) then raise exception 'OWNER_ONLY'; end if;
  update public.hc_invite_links set revoked_at=now() where token=p_token;
end; $$;

revoke all on function public.hc_create_invite_link(uuid,public.hc_role,integer,integer) from public, anon;
revoke all on function public.hc_accept_invite_link(uuid) from public, anon;
revoke all on function public.hc_revoke_invite_link(uuid) from public, anon;
grant execute on function public.hc_create_invite_link(uuid,public.hc_role,integer,integer) to authenticated;
grant execute on function public.hc_accept_invite_link(uuid) to authenticated;
grant execute on function public.hc_revoke_invite_link(uuid) to authenticated;
