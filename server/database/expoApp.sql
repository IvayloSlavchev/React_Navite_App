CREATE DATABASE expoApp;
USE expoApp;

CREATE TABLE users(
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password VARCHAR(60) NOT NULL,
    email VARCHAR(50) NOT NULL
);