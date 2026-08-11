create table public.profiles (
  id uuid primary key,
  user_id uuid not null,
  full_name text,
  email text
);

create table public.orders (
  id uuid primary key,
  user_id uuid not null,
  total_cents integer
);

alter table public.orders enable row level security;

-- rls.permissive: placeholder policy left in place
create policy "orders_all" on public.orders for select using (true);
create policy "orders_insert" on public.orders for insert to anon with check (true);
