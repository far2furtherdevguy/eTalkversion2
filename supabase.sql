-- Run once in Supabase: SQL Editor -> New query -> paste -> Run
create table profiles(
  id uuid primary key references auth.users on delete cascade,
  username text unique not null check (char_length(username) between 3 and 20),
  avatar_url text,
  created_at timestamptz default now());
alter table profiles enable row level security;
create policy "public read" on profiles for select using (true);
create policy "own insert" on profiles for insert with check (auth.uid() = id);
create policy "own update" on profiles for update using (auth.uid() = id);
insert into storage.buckets (id, name, public) values ('avatars','avatars',true) on conflict do nothing;
create policy "avatar read" on storage.objects for select using (bucket_id = 'avatars');
create policy "avatar insert" on storage.objects for insert to authenticated with check (bucket_id = 'avatars' and name like auth.uid()::text || '%');
create policy "avatar update" on storage.objects for update to authenticated using (bucket_id = 'avatars' and name like auth.uid()::text || '%');
