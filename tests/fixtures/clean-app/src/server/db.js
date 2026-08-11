const { Pool } = require("pg");
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Parameter binding, not string building.
async function findUser(email) {
  return pool.query("SELECT * FROM users WHERE email = $1", [email]);
}
module.exports = { findUser };
