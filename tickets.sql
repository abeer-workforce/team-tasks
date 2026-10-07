begin;
create table public.wf_departments(id uuid primary key default gen_random_uuid(),name text not null check(length(trim(name)) between 1 and 150),owner_id uuid not null references public.wf_profiles(id),created_at timestamptz not null default now());
create index on public.wf_departments(owner_id);
alter table public.wf_profiles drop constraint wf_profiles_role_check;
alter table public.wf_profiles add constraint wf_profiles_role_check check(role in ('manager','employee','department_manager'));
alter table public.wf_profiles add column department_id uuid references public.wf_departments(id);
create index on public.wf_profiles(department_id);
alter table public.wf_profiles add constraint wf_department_role check((role='department_manager' and department_id is not null) or (role<>'department_manager' and department_id is null));
create table public.wf_tickets(id uuid primary key default gen_random_uuid(),number bigint generated always as identity unique,created_by uuid not null references public.wf_profiles(id),department_id uuid not null references public.wf_departments(id),title text not null check(length(trim(title)) between 1 and 150),description text not null check(length(trim(description)) between 1 and 5000),priority text not null check(priority in ('عادية','متوسطة','عالية')),due_date date not null,status integer not null default 0 check(status between 0 and 4),version integer not null default 1,created_at timestamptz not null default now(),updated_at timestamptz not null default now());
create index on public.wf_tickets(created_by); create index on public.wf_tickets(department_id);
create table public.wf_ticket_events(id bigint generated always as identity primary key,ticket_id uuid not null references public.wf_tickets(id),actor uuid not null references public.wf_profiles(id),actor_name text not null,body text not null check(length(body) between 1 and 6000),created_at timestamptz not null default now());
create index on public.wf_ticket_events(ticket_id,created_at); create index on public.wf_ticket_events(actor);
alter table public.wf_departments enable row level security; alter table public.wf_tickets enable row level security; alter table public.wf_ticket_events enable row level security;
revoke all on public.wf_departments,public.wf_tickets,public.wf_ticket_events from public,anon,authenticated;
grant select on public.wf_departments,public.wf_tickets,public.wf_ticket_events to authenticated;
create function wf_private.ticket_access(p_id uuid) returns boolean language sql stable security definer set search_path='' as $$ select exists(select 1 from public.wf_profiles p join public.wf_tickets t on t.id=p_id where p.id=auth.uid() and p.active and ((p.role='manager' and t.created_by=p.id) or (p.role='department_manager' and p.department_id=t.department_id))); $$;
create function wf_private.department_access(p_id uuid) returns boolean language sql stable security definer set search_path='' as $$ select exists(select 1 from public.wf_profiles p join public.wf_departments d on d.id=p_id where p.id=auth.uid() and p.active and ((p.role='manager' and d.owner_id=p.id) or (p.role='department_manager' and p.department_id=d.id))); $$;
create policy ticket_read on public.wf_tickets for select to authenticated using(wf_private.ticket_access(id));
create policy ticket_event_read on public.wf_ticket_events for select to authenticated using(wf_private.ticket_access(ticket_id));
create policy department_read on public.wf_departments for select to authenticated using(wf_private.department_access(id));
create function wf_private.ticket_create(p_title text,p_description text,p_department uuid,p_due date,p_priority text) returns uuid language plpgsql security definer set search_path='' as $$
declare v uuid; n text;
begin
 if not wf_private.wf_is_manager() or not wf_private.department_access(p_department) then raise exception 'FORBIDDEN'; end if;
 insert into public.wf_tickets(created_by,department_id,title,description,due_date,priority) values(auth.uid(),p_department,trim(p_title),trim(p_description),p_due,p_priority) returning id into v;
 select display_name into n from public.wf_profiles where id=auth.uid();
 insert into public.wf_ticket_events(ticket_id,actor,actor_name,body) values(v,auth.uid(),n,'تم إرسال التذكرة للإدارة'); return v;
end; $$;
create function wf_private.ticket_update(p_ticket uuid,p_version integer,p_status integer,p_reply text) returns void language plpgsql security definer set search_path='' as $$
declare t public.wf_tickets; n text; labels text[]:=array['جديدة','قيد المعالجة','بانتظار إفادة','تمت المعالجة - بانتظار الاعتماد','مغلقة'];
begin
 if not wf_private.ticket_access(p_ticket) then raise exception 'FORBIDDEN'; end if;
 select * into t from public.wf_tickets where id=p_ticket for update;
 if p_version is null or p_version<>t.version then raise exception 'CONFLICT'; end if;
 if p_status is null or p_status not between 0 and 4 or p_reply is null or length(p_reply)>5000 then raise exception 'INVALID_INPUT'; end if;
 if t.created_by<>auth.uid() and (p_status=4 or t.status=4) then raise exception 'MANAGER_APPROVAL_REQUIRED'; end if;
 if p_status=t.status and length(trim(p_reply))=0 then raise exception 'REPLY_REQUIRED'; end if;
 if p_status=3 and length(trim(p_reply))=0 then raise exception 'REPLY_REQUIRED'; end if;
 select display_name into n from public.wf_profiles where id=auth.uid();
 insert into public.wf_ticket_events(ticket_id,actor,actor_name,body) values(p_ticket,auth.uid(),n,case when p_status<>t.status then 'الحالة: '||labels[p_status+1]||E'\n' else '' end||trim(p_reply));
 update public.wf_tickets set status=p_status,version=version+1,updated_at=now() where id=p_ticket;
end; $$;
create function wf_private.ticket_storage(p_path text,p_write boolean default false) returns boolean language plpgsql stable security definer set search_path='' as $$
declare v uuid;
begin
 v:=split_part(p_path,'/',1)::uuid;
 return wf_private.ticket_access(v) and (not p_write or exists(select 1 from public.wf_tickets where id=v and status<>4));
exception when invalid_text_representation then return false;
end; $$;
create function public.wf_ticket_create(p_title text,p_description text,p_department uuid,p_due date,p_priority text) returns uuid language sql security invoker set search_path='' as $$ select wf_private.ticket_create(p_title,p_description,p_department,p_due,p_priority); $$;
create function public.wf_ticket_update(p_ticket uuid,p_version integer,p_status integer,p_reply text) returns void language sql security invoker set search_path='' as $$ select wf_private.ticket_update(p_ticket,p_version,p_status,p_reply); $$;
revoke all on function wf_private.ticket_access(uuid),wf_private.department_access(uuid),wf_private.ticket_create(text,text,uuid,date,text),wf_private.ticket_update(uuid,integer,integer,text),wf_private.ticket_storage(text,boolean),public.wf_ticket_create(text,text,uuid,date,text),public.wf_ticket_update(uuid,integer,integer,text) from public,anon,authenticated;
grant execute on function wf_private.ticket_access(uuid),wf_private.department_access(uuid),wf_private.ticket_create(text,text,uuid,date,text),wf_private.ticket_update(uuid,integer,integer,text),wf_private.ticket_storage(text,boolean),public.wf_ticket_create(text,text,uuid,date,text),public.wf_ticket_update(uuid,integer,integer,text) to authenticated;
insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types) select 'wf-ticket-files','wf-ticket-files',false,file_size_limit,allowed_mime_types from storage.buckets where id='wf-attachments';
create policy ticket_file_read on storage.objects for select to authenticated using(bucket_id='wf-ticket-files' and wf_private.ticket_storage(name,false));
create policy ticket_file_upload on storage.objects for insert to authenticated with check(bucket_id='wf-ticket-files' and wf_private.ticket_storage(name,true));
-- Department accounts cannot access workforce tasks even if assigned accidentally.
create or replace function wf_private.wf_can_access(p_task uuid) returns boolean language sql stable security definer set search_path='' as $$ select exists(select 1 from public.wf_profiles p join public.wf_tasks t on t.id=p_task where p.id=auth.uid() and p.active and (p.role='manager' or (p.role='employee' and t.assignee=p.id))); $$;
commit;
