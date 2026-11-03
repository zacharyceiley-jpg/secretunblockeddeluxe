-- Keep the Publisher helper invoker-safe and let Admins gift Publisher via a narrow RLS policy.
create or replace function public.has_publisher_role()
returns boolean
language sql
stable
security invoker
set search_path = public, pg_temp
as $$
  select auth.uid() is not null
     and exists (
       select 1
       from public.user_role_ownership
       where user_id = (select auth.uid())
         and role = 'publisher'
     );
$$;

revoke all on function public.has_publisher_role() from public, anon;
grant execute on function public.has_publisher_role() to authenticated;

drop function if exists public.admin_gift_role(uuid, text);

drop policy if exists user_role_ownership_admin_gift_publisher on public.user_role_ownership;
create policy user_role_ownership_admin_gift_publisher
on public.user_role_ownership
for insert
to authenticated
with check (public.is_admin() and role = 'publisher');
