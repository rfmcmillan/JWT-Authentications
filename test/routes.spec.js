const {
  models: { User },
  syncAndSeed,
} = require('../db');
const jwt = require('jsonwebtoken');
const { expect } = require('chai');
const app = require('supertest')(require('../app'));

describe('Routes', () => {
  let seed;
  beforeEach(async () => (seed = await syncAndSeed()));
  describe('seeded data', () => {
    it('there are 3 users', () => {
      expect(Object.keys(seed.users).length).to.equal(3);
    });
  });
  describe('POST /api/auth', () => {
    describe('with valid credentials', () => {
      it('returns a token', async () => {
        const response = await app
          .post('/api/auth')
          .send({ username: 'larry', password: 'larry_pw' });
        expect(response.status).to.equal(200);
        expect(response.body.token).to.be.ok;
      });
    });

    describe('with invalid credentials', () => {
      it('returns a token', async () => {
        const response = await app
          .post('/api/auth')
          .send({ username: 'larry', password: 'larry' });
        expect(response.status).to.equal(401);
        expect(response.body.error).to.equal('bad credentials');
        console.log(response.body);
      });
    });
  });

  describe('GET /api/auth', () => {
    describe('with valid token', () => {
      it('returns a user', async () => {
        const token = await jwt.sign(
          { id: seed.users.lucy.id },
          process.env.JWT
        );
        const response = await app
          .get('/api/auth')
          .set({ authorization: token });
        expect(response.status).to.equal(200);
        expect(response.body.username).to.equal('lucy');
      });
    });
  });
});
