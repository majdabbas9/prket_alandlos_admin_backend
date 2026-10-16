// Runs before each test file (jest.config.js setupFiles). dotenv never overrides variables that
// are already set, so these win over .env: no unit test can sign with the real JWT secret or
// send a query to the real D1 database.
process.env.JWT_SECRET = 'unit-test-jwt-secret';
process.env.CLOUDFLARE_ACCOUNT_ID = 'test-account';
process.env.CLOUDFLARE_DATABASE_ID = 'test-database';
process.env.CLOUDFLARE_API_TOKEN = 'test-api-token';
process.env.LOG_LEVEL = 'silent';
