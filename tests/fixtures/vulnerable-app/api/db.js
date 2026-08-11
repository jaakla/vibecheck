const { Pool } = require("pg");
const pool = new Pool();
const crypto = require("crypto");

// inject.sql: string-built query
async function findUser(email) {
  return pool.query(`SELECT * FROM users WHERE email = '${email}'`);
}

// arch.handrolled_auth: weak hash + Math.random session token
function hashPassword(pw) {
  return crypto.createHash("md5").update(pw).digest("hex");
}
function newSessionToken() {
  return Math.random().toString(36).slice(2);
}
module.exports = { findUser, hashPassword, newSessionToken };
