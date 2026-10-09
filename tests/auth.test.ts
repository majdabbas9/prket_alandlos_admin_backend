import request from 'supertest';
import app from '../src/app';
import bcrypt from 'bcryptjs';

// Mock the D1 utility so tests can run without real Cloudflare credentials
jest.mock('../src/utils/d1', () => ({
  getUserByUsername: jest.fn(async (username: string) => {
    if (username === 'admin') {
      const hash = await bcrypt.hash('admin', 10);
      return { username: 'admin', password_hash: hash, role: 'admin' };
    }
    return null;
  }),
  updatePassword: jest.fn(async (_username: string, _passwordHash: string) => {
    return;
  }),
}));

describe('Auth Endpoints', () => {
  let token = '';

  it('should login with valid credentials and return a token', async () => {
    const res = await request(app).post('/auth/login').send({
      username: 'admin',
      password: 'admin',
    });

    expect(res.statusCode).toEqual(200);
    expect(res.body).toHaveProperty('success', true);
    expect(res.body).toHaveProperty('token');

    token = res.body.token; // Save token for next tests
  });

  it('should fail to login with invalid credentials', async () => {
    const res = await request(app).post('/auth/login').send({
      username: 'wrong',
      password: 'password',
    });

    expect(res.statusCode).toEqual(401);
    expect(res.body).toHaveProperty('success', false);
  });

  it('should validate a valid token', async () => {
    const res = await request(app).post('/auth/validate').set('Authorization', `Bearer ${token}`);

    expect(res.statusCode).toEqual(200);
    expect(res.body).toHaveProperty('success', true);
    expect(res.body.data).toHaveProperty('username', 'admin');
  });

  it('should fail to validate an invalid token', async () => {
    const res = await request(app)
      .post('/auth/validate')
      .set('Authorization', `Bearer invalidtoken`);

    expect(res.statusCode).toEqual(401);
    expect(res.body).toHaveProperty('success', false);
  });

  it('should change the password successfully when credentials are correct', async () => {
    const res = await request(app)
      .post('/auth/change-password')
      .set('Authorization', `Bearer ${token}`)
      .send({
        currentPassword: 'admin',
        newPassword: 'newadminpassword',
      });

    expect(res.statusCode).toEqual(200);
    expect(res.body).toHaveProperty('success', true);
    expect(res.body).toHaveProperty('message', 'Password changed successfully');
  });

  it('should fail to change the password when current password is incorrect', async () => {
    const res = await request(app)
      .post('/auth/change-password')
      .set('Authorization', `Bearer ${token}`)
      .send({
        currentPassword: 'wrongpassword',
        newPassword: 'newadminpassword',
      });

    expect(res.statusCode).toEqual(401);
    expect(res.body).toHaveProperty('success', false);
    expect(res.body).toHaveProperty('message', 'Incorrect current password');
  });

  it('should fail to change the password when token is invalid', async () => {
    const res = await request(app)
      .post('/auth/change-password')
      .set('Authorization', `Bearer invalidtoken`)
      .send({
        currentPassword: 'admin',
        newPassword: 'newadminpassword',
      });

    expect(res.statusCode).toEqual(401);
    expect(res.body).toHaveProperty('success', false);
  });
});
