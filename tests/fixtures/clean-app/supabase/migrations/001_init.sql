create table public.profiles (
  id uuid primary key,
  user_id uuid not null references auth.users(id),
  full_name text
);
alter table public.profiles enable row level security;

create policy "profiles_select_own" on public.profiles
  for select using (auth.uid() = user_id);
create policy "profiles_update_own" on public.profiles
  for update using (auth.uid() = user_id) with check (auth.uid() = user_id);

create table public.orders (
  id uuid primary key,
  user_id uuid not null references auth.users(id),
  total_cents integer not null
);
alter table public.orders enable row level security;

create policy "orders_select_own" on public.orders
  for select using (auth.uid() = user_id);
