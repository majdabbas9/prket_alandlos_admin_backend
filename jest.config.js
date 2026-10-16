/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  testMatch: ['**/*.test.ts'],
  // Fake secrets/credentials before any module loads, so unit tests never use .env's real
  // JWT secret or reach the real (shared) D1 database
  setupFiles: ['<rootDir>/tests/setup-env.ts'],
  verbose: true,
  forceExit: true,
};
