# Dockify

Create a `.env` file
```
DB_HOST=
DB_PORT=
DB_USER=
DB_PASSWORD=
DB_NAME=
SESSION_SECRET=
MAIL_HOST=
MAIL_PORT=
MAIL_SECURE=
MAIL_USER=
MAIL_PASSWORD=
MAIL_ORIGIN_ADDRESS=
```

Query a `mysql or mariadb` database
```
CREATE DATABASE IF NOT EXISTS dockify;

USE dockify;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
	reset_token VARCHAR(255),
	reset_expires DATETIME,
	role VARCHAR(50) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME,
    verified BOOLEAN DEFAULT FALSE,
    verification_token VARCHAR(255),
    new_email VARCHAR(255),
    email_change_token VARCHAR(64),
    twofa_secret VARCHAR(255) DEFAULT NULL,
    twofa_enabled BOOLEAN DEFAULT FALSE
);

CREATE TABLE audit_logs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NULL,
  action VARCHAR(50) NOT NULL,
  details JSON NULL,
  ip_address VARCHAR(45) NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
```
If you are using a docker-based setup, you have to make sure to create the root user for external networking with all privileges
```
CREATE USER 'root'@'%' IDENTIFIED BY '';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
```
You can give yourself the administrator role
```
UPDATE users 
SET role = 'admin' 
WHERE email = 'specific_user@example.com';
```