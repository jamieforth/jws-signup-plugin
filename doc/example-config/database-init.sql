-- Example script for initialising a ws account database.
-- Based on <http://static.springsource.org/spring-security/site/docs/3.1.x/reference/appendix-schema.html>

DROP DATABASE IF EXISTS ws_accounts;
CREATE DATABASE ws_accounts;

GRANT SELECT, INSERT, UPDATE, DELETE
ON ws_accounts.*
TO 'ws_admin'@'localhost';

USE ws_accounts;

create table users (
       username varchar(50) not null primary key,
       password char(80) not null,
       enabled boolean not null
       );
	 
create table authorities (
       username varchar(50) not null,
       authority varchar(50) not null,
       foreign key (username) references users (username),
       unique index authorities_idx_1 (username, authority)
       );

create table groups (
       id bigint unsigned not null auto_increment primary key,
       group_name varchar(50) not null
       );
	 
create table group_authorities (
       group_id bigint unsigned not null,
       authority varchar(50) not null,
       foreign key (group_id) references groups (id)
       );
	 
create table group_members (
       id bigint unsigned not null auto_increment primary key,
       username varchar(50) not null,
       group_id bigint unsigned not null,
       foreign key (group_id) references groups (id)
       );

insert into groups (group_name)
       values ('ws_user');

-- Give members of the 'ws_user' group the authority to 'logon'.
insert into group_authorities (group_id, authority)
       values ((select id from groups where group_name = 'ws_user'),
       	      'logon');

-- Some other jwebsocket plugin authorities.
-- 'org.jwebsocket.plugins.system.send'
-- 'org.jwebsocket.plugins.channels.getChannels'
-- 'org.jwebsocket.plugins.channels.subscribe'
-- 'org.jwebsocket.plugins.channels.publish'

