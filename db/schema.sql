-- Schema for web service produit
------------------------------------------------------
DROP SCHEMA IF EXISTS security CASCADE;
CREATE SCHEMA security
    AUTHORIZATION postgres;

COMMENT ON SCHEMA security
    IS 'schema de gestion de la sécuriter';

------------------------------------------------------
-- for delete table
------------------------------------------------------
drop table IF EXISTS security.app_role CASCADE;
drop table IF EXISTS security.app_user CASCADE;
drop table IF EXISTS security.user_role CASCADE;

------------------------------------------------------
-- role
------------------------------------------------------
CREATE TABLE security.app_role
(
    id_Role  serial primary key,
    roleName varchar(30) not null
);

------------------------------------------------------
-- user
------------------------------------------------------
CREATE TABLE security.app_user
(
    id_user   serial primary key,
    firstName varchar(250) NOT NULL,
    password  varchar(255) NOT NULL,
    lastName  varchar(255),
    email     varchar(255)

);

------------------------------------------------------
-- user_role : associative table
------------------------------------------------------
CREATE TABLE security.user_role
(

    id_user integer NOT NULL references security.app_user (id_user),
    id_Role integer NOT NULL references security.app_role (id_Role),

    CONSTRAINT PK_user_role PRIMARY KEY (id_user, id_Role)

);
