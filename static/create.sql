CREATE TABLE contacts
(user_id INTEGER, first_name TEXT, last_name TEXT, email TEXT, phone TEXT,
school TEXT, company TEXT, street_address TEXT, category TEXT, notes TEXT, favorite BINARY,
date TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users(id))