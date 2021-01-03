
insert into security.app_role(roleName)
values ('ADMIN'),
       ('USER');

insert into security.app_user(firstName,lastName, password, email)
values ('maxime', 'ghalem', '123456', 'maxime@gmail.com'),
       ('sylvain', 'syl-firstName', '123456', 'sylvain@gmail.com');


insert into security.user_role(id_user, id_Role)
values ('1', '1'),
       ('1', '2'),
       ('2', '2');



