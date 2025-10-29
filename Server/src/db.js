import Logger from './logging.js';
import sqlite3 from 'sqlite3';

const logger = new Logger('db');

const sqlite = new sqlite3.verbose();

class Database {
  constructor(name) {
    this.db = new sqlite.Database(`./database/${name}`, (err) => {
      if (err) {
        logger.error('Could not connect to database', err);
      } else {
        logger.info('Connected to SQLite database');
      }
    });
  }

  async get(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.get(sql, params, (err, row) => {
        if (err) {
          logger.error('DB get error', err);
          reject(err);
        } else {
          // Return empty object if no row found
          resolve(row || {});
        }
      });
    });
  }

  // Promise-based single row query
  async getOne(sql, params = [], mapFn = (row) => row) {
    return new Promise((resolve, reject) => {
      this.db.get(sql, params, (err, row) => {
        if (err) {
          logger.error('DB getOne error', err);
          reject(err);
        } else {
          resolve(row ? mapFn(row) : null);
        }
      });
    });
  }

  // Promise-based multiple rows query
  async getAll(sql, params = [], mapFn = (row) => row) {
    return new Promise((resolve, reject) => {
      this.db.all(sql, params, (err, rows) => {
        if (err) {
          logger.error('DB getAll error', err);
          reject(err);
        } else {
          resolve(rows.map(mapFn));
        }
      });
    });
  }

  // Promise-based run for INSERT, UPDATE, DELETE
  async run(sql, params = []) {
    return new Promise((resolve, reject) => {
      this.db.run(sql, params, function(err) {
        if (err) {
          logger.error('DB run error: ', err);
          reject(err);
        } else {
          resolve(this); // return the statement object
        }
      });
    });
  }

}

export default Database;