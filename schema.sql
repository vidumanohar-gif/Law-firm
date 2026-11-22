-- STAGE 1: advocate profiles, photos, security rules. Paste all of this into Supabase > SQL Editor > Run.

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  phone text,
  full_name text,
  email text,
  enrolment_no text,
  bar_association text,
  photo_url text,
  onboarded boolean not null default false,
  status text not null default 'active' check (status in ('active','suspended')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.profiles enable row level security;
drop policy if exists "read own profile" on public.profiles;
drop policy if exists "update own profile" on public.profiles;
create policy "read own profile" on public.profiles for select using (auth.uid() = id);
create policy "update own profile" on public.profiles for update using (auth.uid() = id) with check (auth.uid() = id);

-- An advocate can never change their own status (suspension is for the admin, added in Stage 4).
create or replace function public.guard_profile() returns trigger language plpgsql as $$
begin
  if new.status is distinct from old.status and auth.role() = 'authenticated' then
    raise exception 'status cannot be changed by the account holder';
  end if;
  new.id := old.id; new.updated_at := now();
  return new;
end $$;
drop trigger if exists guard_profile on public.profiles;
create trigger guard_profile before update on public.profiles for each row execute function public.guard_profile();

-- Create a profile automatically when a new advocate verifies their phone.
create or replace function public.handle_new_user() returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, phone) values (new.id, new.phone) on conflict (id) do nothing;
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();

-- Keep the profile phone number in step when the advocate changes their number.
create or replace function public.sync_phone() returns trigger language plpgsql security definer set search_path = public as $$
begin
  update public.profiles set phone = new.phone where id = new.id;
  return new;
end $$;
drop trigger if exists on_auth_phone_changed on auth.users;
create trigger on_auth_phone_changed after update of phone on auth.users for each row execute function public.sync_phone();

-- Profile photo storage (images only, max 2 MB, each advocate writes only to their own folder).
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('avatars', 'avatars', true, 2097152, array['image/jpeg','image/png','image/webp'])
on conflict (id) do nothing;
drop policy if exists "avatar insert own" on storage.objects;
drop policy if exists "avatar update own" on storage.objects;
drop policy if exists "avatar select own" on storage.objects;
drop policy if exists "avatar delete own" on storage.objects;
create policy "avatar insert own" on storage.objects for insert to authenticated with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "avatar update own" on storage.objects for update to authenticated using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "avatar select own" on storage.objects for select to authenticated using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "avatar delete own" on storage.objects for delete to authenticated using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
