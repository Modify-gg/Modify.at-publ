create table if not exists public.users (
  id text primary key,
  username text not null unique,
  email text not null unique,
  password_hash text,
  auth_provider text not null default 'local',
  google_id text,
  role text not null default 'user',
  created_at timestamptz not null default now()
);

create table if not exists public.games (
  id text primary key,
  name text not null unique,
  slug text not null unique,
  categories jsonb not null default '[]'::jsonb,
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
  download_count integer not null default 0,
  verification_status text not null default 'unverified',
  author_id text not null references public.users(id) on delete cascade,
  author_name text not null,
  comments jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now()
);

insert into storage.buckets (id, name, public)
values ('mods', 'mods', false)
on conflict (id) do nothing;
