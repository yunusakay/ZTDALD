
# Zero Trust ve Legacy

```sql
DROP DATABASE IF EXISTS ZTALDB;
CREATE DATABASE IF NOT EXISTS ZTALDB;
USE ZTALDB;

DROP TABLE IF EXISTS l_vault;
DROP TABLE IF EXISTS l_users;
DROP TABLE IF EXISTS zt_vault;
DROP TABLE IF EXISTS zt_users;

CREATE TABLE IF NOT EXISTS l_users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  role VARCHAR(20) NOT NULL
);

CREATE TABLE IF NOT EXISTS l_vault (
  id INT AUTO_INCREMENT PRIMARY KEY,
  service VARCHAR(100) NOT NULL,
  username VARCHAR(100) NOT NULL,
  password VARCHAR(255) NOT NULL,
  sensitivity VARCHAR(20) NOT NULL
);

CREATE TABLE IF NOT EXISTS zt_users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  role VARCHAR(20) NOT NULL
);

CREATE TABLE IF NOT EXISTS zt_vault (
  id INT AUTO_INCREMENT PRIMARY KEY,
  service VARCHAR(100) NOT NULL,
  username VARCHAR(100) NOT NULL,
  password TEXT NOT NULL,
  sensitivity VARCHAR(20) NOT NULL
);

INSERT INTO l_users (username, password, role) VALUES
('admin', '1', 'admin'),
('tech',  '1', 'tech'),
('intern','1','intern');

INSERT INTO zt_users (username, password, role) VALUES
('admin', '1', 'admin'),
('tech',  '1', 'tech'),
('intern','1','intern');
```

Legacy: `http://localhost/ZTAL/L/index.php`

Zero Trust: `http://localhost/ZTAL/ZT/index.php`

