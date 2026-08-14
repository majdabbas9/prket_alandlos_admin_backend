import dotenv from 'dotenv';
dotenv.config();

const {
  CLOUDFLARE_ACCOUNT_ID,
  CLOUDFLARE_DATABASE_ID,
  CLOUDFLARE_API_TOKEN_D1,
} = process.env;

/**
 * Execute a SQL query against Cloudflare D1 via REST API
 */
export const queryD1 = async (sql: string, params: any[] = []) => {

  if (!CLOUDFLARE_ACCOUNT_ID || !CLOUDFLARE_DATABASE_ID || !CLOUDFLARE_API_TOKEN_D1) {
    throw new Error('Cloudflare credentials are not configured in .env');
  }

  const url = `https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/d1/database/${CLOUDFLARE_DATABASE_ID}/query`;

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${CLOUDFLARE_API_TOKEN_D1}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ sql, params }),
  });

  const data: any = await response.json();

  if (!data.success) {
    console.error('D1 Query Error:', data.errors);
    throw new Error(data.errors[0]?.message || 'Database query failed');
  }

  // D1 returns an array of result objects per statement
  return data.result[0].results;
};

export const getUserByUsername = async (username: string) => {
  const results = await queryD1('SELECT * FROM users WHERE username = ?', [username]);
  return results.length > 0 ? results[0] : null;
};
