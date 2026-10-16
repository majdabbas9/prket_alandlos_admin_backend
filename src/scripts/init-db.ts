import { queryD1 } from '../utils/d1';
import bcrypt from 'bcryptjs';

// The admin's credentials come from the environment (like prket_alandlos_infra's
// seed/provision.mjs); there is deliberately no default password.
const MIN_PASSWORD_LENGTH = 12;

export const initDb = async () => {
  const adminUsername = process.env.ADMIN_USERNAME || 'admin';
  const adminPassword = process.env.ADMIN_PASSWORD ?? '';
  if (adminPassword.length < MIN_PASSWORD_LENGTH || adminPassword === adminUsername) {
    console.error(
      `ADMIN_PASSWORD must be set, at least ${MIN_PASSWORD_LENGTH} characters, and differ from the username.`,
    );
    return;
  }

  console.log('Initializing D1 Database...');

  try {
    // 1. Create table
    await queryD1(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'admin'
      )
    `);
    console.log('Table `users` created or already exists.');

    // 2. Check if admin exists
    const users = await queryD1('SELECT * FROM users WHERE username = ?', [adminUsername]);

    if (users.length === 0) {
      // 3. Insert the admin
      const salt = await bcrypt.genSalt(10);
      const hash = await bcrypt.hash(adminPassword, salt);

      await queryD1('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)', [
        adminUsername,
        hash,
        'admin',
      ]);
      console.log(`Admin user "${adminUsername}" inserted successfully.`);
    } else {
      console.log('Admin user already exists. Skipping insertion.');
    }

    console.log('Database initialization completed.');
  } catch (error) {
    console.error('Failed to initialize database:', error);
  }
};

// Run when executed directly (npm run db:init), not when imported
if (require.main === module) {
  initDb();
}
