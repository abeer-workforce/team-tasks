-- Run once in a NEW Supabase project. No real employee data is included.
begin;
create table public.wf_profiles (
 id uuid primary key references auth.users(id) on delete cascade,
 display_name text not null check(length(display_name) between 1 and 100),
 role text not null default 'employee' check(role in ('manager','employee')),
 active boolean not null default true
);
create table public.wf_tasks (
 id uuid primary key default gen_random_uuid(),
 title text not null check(length(trim(title)) between 1 and 150),
 description text not null default '' check(length(description)<=3000),
 assignee uuid not null references public.wf_profiles(id),
 due_date date not null,
 priority text not null check(priority in ('عادية','متوسطة','عالية')),
 status integer not null default 0 check(status between 0 and 4),
 created_by uuid not null references auth.users(id),
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now(),
 version integer not null default 1
);
create table public.wf_events (
 id bigint generated always as identity primary key,
 task_id uuid not null references public.wf_tasks(id) on delete cascade,
 actor uuid not null references public.wf_profiles(id),
 actor_name text not null,
 body text not null,
 created_at timestamptz not null default now()
);
create index on public.wf_tasks(assignee);
create index on public.wf_events(task_id,created_at);
alter table public.wf_profiles enable row level security;
alter table public.wf_tasks enable row level security;
alter table public.wf_events enable row level security;
create function public.wf_is_manager() returns boolean language sql stable security definer set search_path='' as $$
 select exists(select 1 from public.wf_profiles where id=auth.uid() and active and role='manager');
$$;
create function public.wf_can_access(p_task uuid) returns boolean language sql stable security definer set search_path='' as $$
 select exists(select 1 from public.wf_profiles p join public.wf_tasks t on t.id=p_task where p.id=auth.uid() and p.active and (p.role='manager' or t.assignee=p.id));
$$;
create policy wf_profiles_read on public.wf_profiles for select to authenticated using(id=auth.uid() or public.wf_is_manager());
create policy wf_tasks_read on public.wf_tasks for select to authenticated using(public.wf_can_access(id));
create policy wf_events_read on public.wf_events for select to authenticated using(public.wf_can_access(task_id));
revoke all on public.wf_profiles,public.wf_tasks,public.wf_events from anon,authenticated;
grant select on public.wf_profiles,public.wf_tasks,public.wf_events to authenticated;
create function public.wf_create_task(p_title text,p_description text,p_assignee uuid,p_due date,p_priority text) returns uuid language plpgsql security definer set search_path='' as $$
declare v_id uuid; v_name text;
begin
 if not public.wf_is_manager() then raise exception 'FORBIDDEN'; end if;
 if not exists(select 1 from public.wf_profiles where id=p_assignee and active) then raise exception 'INVALID_ASSIGNEE'; end if;
 insert into public.wf_tasks(title,description,assignee,due_date,priority,created_by) values(trim(p_title),p_description,p_assignee,p_due,p_priority,auth.uid()) returning id into v_id;
 select display_name into v_name from public.wf_profiles where id=auth.uid();
 insert into public.wf_events(task_id,actor,actor_name,body) values(v_id,auth.uid(),v_name,'تم إسناد المهمة');
 return v_id;
end; $$;
create function public.wf_update_task(p_task uuid,p_version integer,p_status integer,p_comment text) returns void language plpgsql security definer set search_path='' as $$
declare v_task public.wf_tasks; v_name text; v_labels text[]:=array['جديدة','قيد التنفيذ','بانتظار إفادة','للمراجعة','مكتملة'];
begin
 if not public.wf_can_access(p_task) then raise exception 'FORBIDDEN'; end if;
 select * into v_task from public.wf_tasks where id=p_task for update;
 if v_task.version<>p_version then raise exception 'CONFLICT'; end if;
 if p_status is null or p_status<0 or p_status>4 or p_comment is null or length(p_comment)>3000 then raise exception 'INVALID_INPUT'; end if;
 if not public.wf_is_manager() and (p_status=4 or v_task.status=4) then raise exception 'MANAGER_APPROVAL_REQUIRED'; end if;
 select display_name into v_name from public.wf_profiles where id=auth.uid();
 if v_task.status<>p_status then
 insert into public.wf_events(task_id,actor,actor_name,body) values(p_task,auth.uid(),v_name,'تغيير الحالة: '||v_labels[v_task.status+1]||' ← '||v_labels[p_status+1]);
 end if;
 if length(trim(p_comment))>0 then insert into public.wf_events(task_id,actor,actor_name,body) values(p_task,auth.uid(),v_name,trim(p_comment)); end if;
 update public.wf_tasks set status=p_status,updated_at=now(),version=version+1 where id=p_task;
end; $$;
-- Manager can activate only existing, verified Auth users; no client can grant manager rights.
create function public.wf_add_employee(p_email text,p_name text) returns void language plpgsql security definer set search_path='' as $$
declare v_user uuid;
begin
 if not public.wf_is_manager() then raise exception 'FORBIDDEN'; end if;
 select id into v_user from auth.users where lower(email)=lower(trim(p_email)) and email_confirmed_at is not null;
 if v_user is null then raise exception 'USER_NOT_VERIFIED'; end if;
 insert into public.wf_profiles(id,display_name,role) values(v_user,trim(p_name),'employee');
end; $$;
revoke all on function public.wf_is_manager(), public.wf_can_access(uuid), public.wf_create_task(text,text,uuid,date,text),public.wf_update_task(uuid,integer,integer,text), public.wf_add_employee(text,text) from public,anon;
grant execute on function public.wf_is_manager(), public.wf_can_access(uuid), public.wf_create_task(text,text,uuid,date,text),public.wf_update_task(uuid,integer,integer,text),public.wf_add_employee(text,text) to authenticated;
-- Storage is private. Reads and uploads require a currently authorized task participant.
insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types) values ('wf-attachments','wf-attachments',false,20971520,array['application/pdf','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','application/vnd.ms-excel','application/vnd.openxmlformats-officedocument.wordprocessingml.document','application/msword','application/vnd.openxmlformats-officedocument.presentationml.presentation','application/vnd.ms-powerpoint','text/csv','text/plain','image/png','image/jpeg','application/zip']);
create function public.wf_storage_access(p_path text) returns boolean language plpgsql stable security definer set search_path='' as $$
begin
 return public.wf_can_access(split_part(p_path,'/',1)::uuid);
exception when invalid_text_representation then return false;
end; $$;
revoke all on function public.wf_storage_access(text) from public,anon;
grant execute on function public.wf_storage_access(text) to authenticated;
create policy wf_file_read on storage.objects for select to authenticated using(bucket_id='wf-attachments' and public.wf_storage_access(name));
create policy wf_file_upload on storage.objects for insert to authenticated with check(bucket_id='wf-attachments' and public.wf_storage_access(name));
commit;
-- Bootstrap FIRST manager only in SQL editor, AFTER verifying account email:
-- insert into public.wf_profiles(id,display_name,role)
-- select id,'عبير','manager' from auth.users
-- where lower(email)='OWNER_EMAIL_HERE' and email_confirmed_at is not null;
