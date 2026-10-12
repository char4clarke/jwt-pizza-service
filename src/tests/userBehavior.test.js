const request = require('supertest');
const { randomUUID } = require('node:crypto');
const app = require('../service');
const { DB } = require('../database/database');

let user;
let token;
let credentials;

beforeAll(async () => {
  credentials = { name: 'Integration diner', email: `${randomUUID()}@example.test`, password: randomUUID() };
  const response = await request(app).post('/api/auth').send(credentials).expect(200);
  user = response.body.user;
  token = response.body.token;
  expect(user).not.toHaveProperty('password');
});

afterAll(async () => {
  if (!user) return;
  const connection = await DB.getConnection();
  try {
    for (const table of ['auth', 'userRole']) {
      await connection.execute(`DELETE FROM ${table} WHERE userId=?`, [user.id]);
    }
    await connection.execute('DELETE FROM user WHERE id=?', [user.id]);
  } finally {
    await connection.end();
  }
});

test.each([
  {}, { name: 'Diner' }, { name: 'Diner', email: 'missing@example.test' },
])('rejects incomplete registration: %j', async (body) => {
  const response = await request(app).post('/api/auth').send(body).expect(400);
  expect(response.body.message).toBe('name, email, and password are required');
});

test('rejects incorrect passwords and unknown users', async () => {
  for (const body of [
    { ...credentials, password: randomUUID() },
    { email: `${randomUUID()}@example.test`, password: randomUUID() },
  ]) {
    const response = await request(app).put('/api/auth').send(body).expect(404);
    expect(response.body.message).toBe('unknown user');
  }
});

test('requires authentication and rejects invalid tokens', async () => {
  await request(app).get('/api/user/me').expect(401);
  await request(app).get('/api/user/me').set('Authorization', 'Bearer invalid').expect(401);
  // Exercise signature verification even when a token is present in the session table.
  const invalidToken = `invalid.payload.${randomUUID()}`;
  await DB.loginUser(user.id, invalidToken);
  await request(app).get('/api/user/me').set('Authorization', `Bearer ${invalidToken}`).expect(401);
  await DB.logoutUser(invalidToken);
});

test('returns the authenticated profile and denies updates to other users', async () => {
  const response = await request(app).get('/api/user/me').set('Authorization', `Bearer ${token}`).expect(200);
  expect(response.body).toMatchObject(user);
  expect(response.body).not.toHaveProperty('password');
  await request(app).put(`/api/user/${user.id + 1}`).set('Authorization', `Bearer ${token}`).send({ name: 'Changed' }).expect(403);
});

test('updates profile and password, then revokes the session on logout', async () => {
  const updated = { name: 'Updated diner', email: `${randomUUID()}@example.test`, password: randomUUID() };
  const response = await request(app).put(`/api/user/${user.id}`).set('Authorization', `Bearer ${token}`).send(updated).expect(200);
  expect(response.body.user).toMatchObject({ id: user.id, name: updated.name, email: updated.email });
  expect(response.body.user).not.toHaveProperty('password');
  await request(app).put('/api/auth').send({ email: updated.email, password: credentials.password }).expect(404);
  const login = await request(app).put('/api/auth').send(updated).expect(200);
  await request(app).delete('/api/auth').set('Authorization', `Bearer ${login.body.token}`).expect(200, { message: 'logout successful' });
  await request(app).get('/api/user/me').set('Authorization', `Bearer ${login.body.token}`).expect(401);
});

test('serves welcome, documentation, CORS headers, and unknown-route errors', async () => {
  const home = await request(app).get('/').set('Origin', 'https://example.test').expect(200);
  expect(home.body).toMatchObject({ message: 'welcome to JWT Pizza', version: expect.any(String) });
  expect(home.headers['access-control-allow-origin']).toBe('https://example.test');
  const docs = await request(app).get('/api/docs').expect(200);
  expect(docs.body.endpoints).toEqual(expect.arrayContaining([expect.objectContaining({ path: '/api/auth' })]));
  await request(app).get('/missing').expect(404, { message: 'unknown endpoint' });
  await request(app).post('/api/auth').set('Content-Type', 'application/json').send('{').expect(400);
});

describe('List users', () => {
  test('rejects unauthenticated requests', async () => {
    await request(app)
      .get('/api/user')
      .expect(401);
  });

  test('rejects non-admin users', async () => {
    await request(app)
      .get('/api/user')
      .set('Authorization', `Bearer ${token}`)
      .expect(403);
  });
});


describe('List users functionality', () => {
  let adminToken;
  let adminUser;
  let testUsers = [];
  const prefix = `ListTest-${randomUUID()}`;

  beforeAll(async () => {
    // Create an admin directly through the database
    const adminPassword = 'testAdmin123';
    const adminEmail = `${randomUUID()}@example.test`;

    adminUser = await DB.addUser({
      name: 'Test Admin',
      email: adminEmail,
      password: adminPassword,
      roles: [{ role: 'admin' }],
    });

    const login = await request(app)
      .put('/api/auth')
      .send({ email: adminEmail, password: adminPassword })
      .expect(200);

    adminToken = login.body.token;

    // Create two test diners
    for (const name of [`${prefix}-Alice`, `${prefix}-Bob`]) {
      const created = await DB.addUser({
        name,
        email: `${randomUUID()}@example.test`,
        password: 'test123',
        roles: [{ role: 'diner' }],
      });
      testUsers.push(created);
    }
  });

  afterAll(async () => {
    const connection = await DB.getConnection();
    try {
      for (const created of [...testUsers, adminUser].filter(Boolean)) {
        await connection.execute(
          'DELETE FROM auth WHERE userId = ?',
          [created.id]
        );
        await connection.execute(
          'DELETE FROM userRole WHERE userId = ?',
          [created.id]
        );
        await connection.execute(
          'DELETE FROM user WHERE id = ?',
          [created.id]
        );
      }
    } finally {
      await connection.end();
    }
  });

  test('returns users with roles but no passwords', async () => {
    const res = await request(app)
      .get('/api/user?limit=100')
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(200);

    expect(Array.isArray(res.body.users)).toBe(true);
    expect(typeof res.body.more).toBe('boolean');

    const listedAdmin = res.body.users.find(
      (u) => u.id === adminUser.id
    );

    expect(listedAdmin).toBeDefined();
    expect(listedAdmin.roles).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ role: 'admin' }),
      ])
    );

    for (const user of res.body.users) {
      expect(user).not.toHaveProperty('password');
    }
  });

  test('filters users by name', async () => {
    const res = await request(app)
      .get(`/api/user?name=${encodeURIComponent(prefix + '*')}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(200);

    expect(res.body.users).toHaveLength(2);
    expect(res.body.users.every(
      (u) => u.name.startsWith(prefix)
    )).toBe(true);
  });

  test('paginates users and indicates more results', async () => {
    const filter = encodeURIComponent(prefix + '*');

    const first = await request(app)
      .get(`/api/user?page=1&limit=1&name=${filter}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(200);

    expect(first.body.users).toHaveLength(1);
    expect(first.body.more).toBe(true);

    const second = await request(app)
      .get(`/api/user?page=2&limit=1&name=${filter}`)
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(200);

    expect(second.body.users).toHaveLength(1);
    expect(second.body.more).toBe(false);

    expect(second.body.users[0].id)
      .not.toBe(first.body.users[0].id);
  });

  test('rejects invalid pagination', async () => {
    await request(app)
      .get('/api/user?page=-1&limit=10')
      .set('Authorization', `Bearer ${adminToken}`)
      .expect(400);
  });
});
