create table if not exists roles (id text primary key, name text unique not null, description text not null default '', created_at timestamptz not null default now());
create table if not exists users (
  id text primary key,
  email text unique not null,
  phone text not null default '',
  display_name text not null default '',
  status text not null default 'pending',
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create table if not exists permissions (id text primary key, key text unique not null, resource text not null, action text not null, description text not null default '');
create table if not exists role_permissions (role_id text not null references roles(id) on delete cascade, permission_id text not null references permissions(id) on delete cascade, primary key(role_id, permission_id));
create table if not exists user_roles (user_id text not null, role_id text not null references roles(id) on delete cascade, tenant_id text not null default 'default', created_at timestamptz not null default now(), primary key(user_id, role_id, tenant_id));
create index if not exists idx_user_roles_user on user_roles(user_id, tenant_id);
