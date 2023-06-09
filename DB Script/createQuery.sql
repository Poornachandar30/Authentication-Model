CREATE TABLE users (
  userId INT NOT NULL AUTO_INCREMENT,
  username CHAR(50) NOT NULL,
  email VARCHAR(255) NOT NULL,
  password CHAR(60) NOT NULL,
  last_modified_by CHAR(50),
  last_modified_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  created_by CHAR(50),
  created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (userId),
  UNIQUE KEY (email)
);