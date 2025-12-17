CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, username TEXT NOT NULL, hash TEXT NOT NULL, cash NUMERIC NOT NULL DEFAULT 10000.00);
CREATE TABLE sqlite_sequence(name,seq);
CREATE UNIQUE INDEX username ON users (username);
CREATE TABLE history (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id  INTEGER NOT NULL,
    stock    TEXT NOT NULL,
    shares   REAL NOT NULL,
    price    REAL NOT NULL,
    buy      BOOLEAN NOT NULL,
    time     TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE current_stock (
    user_id INTEGER NOT NULL,
    stock   TEXT NOT NULL,
    shares  REAL NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT current_stock_pk PRIMARY KEY (user_id, stock)
);
CREATE TABLE purchases (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id  INTEGER NOT NULL,
    stock    TEXT NOT NULL,
    shares   REAL NOT NULL,
    price    REAL NOT NULL,
    buy_time TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE TABLE sold (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id  INTEGER NOT NULL,
    stock    TEXT NOT NULL,
    shares   REAL NOT NULL,
    price    REAL NOT NULL,
    sell_time TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);