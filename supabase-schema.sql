create table if not exists public.users (
  id text primary key,
  username text not null unique,
  email text not null unique,
  password_hash text,
  auth_provider text not null default 'local',
  google_id text,
  role text not null default 'user',
  bio text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists public.games (
  id text primary key,
  name text not null unique,
  slug text not null unique,
  categories jsonb not null default '[]'::jsonb,
  icon_file_name text,
  icon_file_path text,
  created_at timestamptz not null default now()
);

create table if not exists public.mods (
  id text primary key,
  slug text not null unique,
  title text not null,
  game_slug text not null references public.games(slug) on update cascade,
  category text not null,
  version text not null,
  summary text not null,
  description text not null,
  file_name text not null,
  file_path text not null,
  original_file_name text not null,
  file_size bigint not null default 0,
  icon_file_name text,
  icon_file_path text,
  gallery_images jsonb not null default '[]'::jsonb,
  install_instructions text,
  changelog jsonb not null default '[]'::jsonb,
  download_count integer not null default 0,
  verification_status text not null default 'unverified',
  platforms jsonb not null default '[]'::jsonb,
  game_versions jsonb not null default '[]'::jsonb,
  dependencies jsonb not null default '[]'::jsonb,
  featured boolean not null default false,
  updated_at timestamptz not null default now(),
  author_id text not null references public.users(id) on delete cascade,
  author_name text not null,
  comments jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists public.reports (
  id text primary key,
  mod_id text not null,
  mod_slug text not null,
  mod_title text not null,
  reporter_id text not null references public.users(id) on delete cascade,
  reporter_name text not null,
  reason text not null,
  details text not null default '',
  status text not null default 'open',
  created_at timestamptz not null default now(),
  resolved_at timestamptz,
  resolved_by text
);

create table if not exists public.activity_log (
  id text primary key,
  actor_id text,
  actor_name text not null,
  action text not null,
  target_type text not null,
  target_id text,
  details text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists public.email_challenges (
  id text primary key,
  email text not null,
  purpose text not null,
  code_hash text not null,
  payload jsonb not null default '{}'::jsonb,
  attempts integer not null default 0,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

create table if not exists public.favorites (
  id text primary key,
  user_id text not null references public.users(id) on delete cascade,
  mod_id text not null references public.mods(id) on delete cascade,
  mod_slug text not null,
  mod_title text not null,
  created_at timestamptz not null default now(),
  unique(user_id, mod_id)
);

create table if not exists public.follows (
  id text primary key,
  user_id text not null references public.users(id) on delete cascade,
  creator_id text not null references public.users(id) on delete cascade,
  creator_name text not null,
  created_at timestamptz not null default now(),
  unique(user_id, creator_id)
);

create table if not exists public.notifications (
  id text primary key,
  user_id text not null references public.users(id) on delete cascade,
  type text not null,
  mod_id text,
  mod_slug text,
  mod_title text,
  title text not null,
  message text not null,
  read boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists public.download_events (
  id text primary key,
  mod_id text not null references public.mods(id) on delete cascade,
  creator_id text not null references public.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

insert into storage.buckets (id, name, public)
values ('mods', 'mods', false)
on conflict (id) do nothing;

alter table public.mods add column if not exists icon_file_name text;
alter table public.mods add column if not exists icon_file_path text;
alter table public.mods add column if not exists gallery_images jsonb not null default '[]'::jsonb;
alter table public.mods add column if not exists install_instructions text;
alter table public.mods add column if not exists changelog jsonb not null default '[]'::jsonb;
alter table public.games add column if not exists icon_file_name text;
alter table public.games add column if not exists icon_file_path text;
alter table public.users add column if not exists bio text not null default '';
alter table public.mods add column if not exists platforms jsonb not null default '[]'::jsonb;
alter table public.mods add column if not exists game_versions jsonb not null default '[]'::jsonb;
alter table public.mods add column if not exists dependencies jsonb not null default '[]'::jsonb;
alter table public.mods add column if not exists featured boolean not null default false;
alter table public.mods add column if not exists updated_at timestamptz not null default now();

-- The Express server is the only database client. Keep the public API roles out.
alter table public.users enable row level security;
alter table public.games enable row level security;
alter table public.mods enable row level security;
alter table public.reports enable row level security;
alter table public.activity_log enable row level security;
alter table public.email_challenges enable row level security;
alter table public.favorites enable row level security;
alter table public.follows enable row level security;
alter table public.notifications enable row level security;
alter table public.download_events enable row level security;
revoke all on table public.users from anon, authenticated, public;
revoke all on table public.games from anon, authenticated, public;
revoke all on table public.mods from anon, authenticated, public;
revoke all on table public.reports from anon, authenticated, public;
revoke all on table public.activity_log from anon, authenticated, public;
revoke all on table public.email_challenges from anon, authenticated, public;
revoke all on table public.favorites from anon, authenticated, public;
revoke all on table public.follows from anon, authenticated, public;
revoke all on table public.notifications from anon, authenticated, public;
revoke all on table public.download_events from anon, authenticated, public;
alter default privileges in schema public revoke all on tables from anon, authenticated;
