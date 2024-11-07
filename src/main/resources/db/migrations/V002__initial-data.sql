INSERT INTO _user (id, username, password, enabled)
VALUES ('5d1d8a85-6f0c-46dd-a035-fb217ec5d8e3', 'admin', '$2a$10$0HP.FlC2DUveTIWB3qTPo.hw.dbiRL694BxTruwCYSQG0x6rrNN5S', true);
INSERT INTO _role (id, name)
VALUES ('cd992bd5-f7fc-47ce-bbbb-f089baee1757', 'ADMIN');
INSERT INTO _user_role (user_id, role_id)
VALUES ('5d1d8a85-6f0c-46dd-a035-fb217ec5d8e3', 'cd992bd5-f7fc-47ce-bbbb-f089baee1757');
