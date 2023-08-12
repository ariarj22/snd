-- Create "articles" table
CREATE TABLE `articles` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `title` text NOT NULL DEFAULT '', `body` text NOT NULL DEFAULT '', `description` text NOT NULL DEFAULT '', `slug` text NOT NULL, `user_id` integer NULL);
-- Create index "articles_slug_key" to table: "articles"
CREATE UNIQUE INDEX `articles_slug_key` ON `articles` (`slug`);
-- Create "users" table
CREATE TABLE `users` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `email` text NOT NULL, `password` text NOT NULL);
-- Create index "users_email_key" to table: "users"
CREATE UNIQUE INDEX `users_email_key` ON `users` (`email`);
-- Create "ymirs" table
CREATE TABLE `ymirs` (`id` integer NOT NULL PRIMARY KEY AUTOINCREMENT, `version` text NOT NULL DEFAULT 'alpha-test-dev1');
