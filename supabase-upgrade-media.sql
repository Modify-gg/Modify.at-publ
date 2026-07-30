alter table public.mods add column if not exists icon_file_name text;
alter table public.mods add column if not exists icon_file_path text;
alter table public.mods add column if not exists gallery_images jsonb not null default '[]'::jsonb;
alter table public.mods add column if not exists install_instructions text;
alter table public.mods add column if not exists changelog jsonb not null default '[]'::jsonb;
