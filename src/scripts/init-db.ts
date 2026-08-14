import { queryD1 } from '../utils/d1';
import bcrypt from 'bcryptjs';

const initDb = async () => {
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
    const users = await queryD1('SELECT * FROM users WHERE username = ?', ['admin']);
    
    if (users.length === 0) {
      // 3. Insert default admin
      const salt = await bcrypt.genSalt(10);
      const hash = await bcrypt.hash('admin', salt);

      await queryD1(
        'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
        ['admin', hash, 'admin']
      );
      console.log('Default admin user inserted successfully (admin/admin).');
    } else {
      console.log('Admin user already exists. Skipping insertion.');
    }

    console.log('Database initialization completed.');
  } catch (error) {
    console.error('Failed to initialize database:', error);
  }
};

initDb();
