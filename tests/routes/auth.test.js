/**
 * Lab 1 - Unit Test
 * Endpoint: POST /api/auth/refresh
 * Student: Pratik Naik
 */




const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../../server');

describe('POST /api/auth/refresh', () => {
  beforeAll(async () => {
    const url = 'mongodb://localhost:27017/pace_test';
    await mongoose.connect(url);
  });

  afterAll(async () => {
    await mongoose.connection.dropDatabase();
    await mongoose.connection.close();
  });

  it('should return new tokens if refresh token is valid', async () => {
    // Register user (use /signup, not /register)
    await request(app).post('/api/auth/signup').send({
      name: 'Refresh User',
      username: 'refreshuser',
      email: 'refresh@example.com',
      password: 'RefreshPass123',
    });

    // Login with email
    const loginRes = await request(app).post('/api/auth/login').send({
      emailOrUsername: 'refresh@example.com',
      password: 'RefreshPass123',
    });

    expect(loginRes.statusCode).toBe(200);
    expect(loginRes.body).toHaveProperty('refreshToken');

    const refreshToken = loginRes.body.refreshToken;

    // Call refresh with refreshToken cookie manually set
    const res = await request(app)
      .post('/api/auth/refresh')
      .set('Cookie', [`refreshToken=${refreshToken}`]);

    expect(res.statusCode).toBe(200);
    expect(res.body).toHaveProperty('success', true);
  });

  it('should return 401 if refresh token missing', async () => {
    const res = await request(app).post('/api/auth/refresh');
    expect(res.statusCode).toBe(401);
    expect(res.body).toHaveProperty('error', 'Missing refresh token');
  });
});
