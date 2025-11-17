/**
 * Lab 1 - Unit Test
 * Endpoint: POST /api/auth/signup
 * Student: Utkarsh Ysadav
 */



// tests/routes/auth.test.js
const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../../server');

describe('Auth Routes', () => {
  beforeAll(async () => {
    const url = 'mongodb://localhost:27017/pace_test';
    await mongoose.connect(url);
  });

  afterAll(async () => {
    await mongoose.connection.dropDatabase();
    await mongoose.connection.close();
  })


  test('POST /api/auth/signup should create a new user', async () => {
    const res = await request(app)
      .post('/api/auth/signup')
      .send({
        name: 'Test User',
        username: 'testuser',
        email: 'test@example.com',
        password: 'TestPass123'
      });

    expect(res.statusCode).toBe(201);
    expect(res.body).toHaveProperty('id');
    expect(res.body).toHaveProperty('name', 'Test User');
    expect(res.body).toHaveProperty('username', 'testuser');
    expect(res.body).toHaveProperty('email', 'test@example.com');
  });
});
