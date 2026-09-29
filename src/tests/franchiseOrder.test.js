const request = require('supertest');
const { randomUUID } = require('node:crypto');
const app = require('../service');
const { DB, Role } = require('../database/database');
const { setAuth } = require('../routes/authRouter');

const users = [];
const franchises = [];
const menuIds = [];
let admin;
let diner;
let owner;

async function createUser(role) {
  const user = await DB.addUser({ name: 'Integration user', email: `${randomUUID()}@example.test`, password: randomUUID(), roles: [{ role }] });
  users.push(user);
  return { ...user, token: await setAuth(user) };
}

async function createFranchise() {
  const response = await request(app).post('/api/franchise').set('Authorization', `Bearer ${admin.token}`)
    .send({ name: `test-${randomUUID()}`, admins: [{ email: owner.email }] }).expect(200);
  franchises.push(response.body.id);
  return response.body;
}

beforeAll(async () => {
  admin = await createUser(Role.Admin);
  diner = await createUser(Role.Diner);
  owner = await createUser(Role.Diner);
});

afterEach(() => jest.restoreAllMocks());

afterAll(async () => {
  const connection = await DB.getConnection();
  try {
    for (const user of users) {
      await connection.execute('DELETE oi FROM orderItem oi JOIN dinerOrder d ON d.id=oi.orderId WHERE d.dinerId=?', [user.id]);
      await connection.execute('DELETE FROM dinerOrder WHERE dinerId=?', [user.id]);
    }
    for (const id of franchises) await DB.deleteFranchise(id);
    for (const id of menuIds) await connection.execute('DELETE FROM menu WHERE id=?', [id]);
    for (const user of users) {
      await connection.execute('DELETE FROM auth WHERE userId=?', [user.id]);
      await connection.execute('DELETE FROM userRole WHERE userId=?', [user.id]);
      await connection.execute('DELETE FROM user WHERE id=?', [user.id]);
    }
  } finally {
    await connection.end();
  }
});

test('restricts franchise and menu creation to administrators', async () => {
  for (const [method, path] of [['post', '/api/franchise'], ['put', '/api/order/menu']]) {
    await request(app)[method](path).send({}).expect(401);
    await request(app)[method](path).set('Authorization', `Bearer ${diner.token}`).send({}).expect(403);
  }
  const response = await request(app).post('/api/franchise').set('Authorization', `Bearer ${admin.token}`)
    .send({ name: `test-${randomUUID()}`, admins: [{ email: `${randomUUID()}@example.test` }] }).expect(404);
  expect(response.body.message).toContain('unknown user for franchise admin');
});

test('creates, lists, and deletes stores and franchises with ownership checks', async () => {
  const franchise = await createFranchise();
  expect(franchise.admins).toEqual([expect.objectContaining({ id: owner.id, email: owner.email })]);
  const storePath = `/api/franchise/${franchise.id}/store`;
  await request(app).post(storePath).set('Authorization', `Bearer ${diner.token}`).send({ name: 'Denied' }).expect(403);
  const store = await request(app).post(storePath).set('Authorization', `Bearer ${owner.token}`).send({ name: 'Test store' }).expect(200);
  expect(store.body).toMatchObject({ franchiseId: franchise.id, name: 'Test store' });

  for (const actor of [null, admin]) {
    let req = request(app).get('/api/franchise').query({ name: franchise.name });
    if (actor) req = req.set('Authorization', `Bearer ${actor.token}`);
    const response = await req.expect(200);
    expect(response.body).toMatchObject({ more: false, franchises: [expect.objectContaining({ id: franchise.id, stores: [expect.objectContaining({ id: store.body.id })] })] });
    if (actor) expect(response.body.franchises[0].admins).toEqual(expect.arrayContaining([expect.objectContaining({ id: owner.id })]));
    else expect(response.body.franchises[0]).not.toHaveProperty('admins');
  }
  const own = await request(app).get(`/api/franchise/${owner.id}`).set('Authorization', `Bearer ${owner.token}`).expect(200);
  expect(own.body).toEqual(expect.arrayContaining([expect.objectContaining({ id: franchise.id })]));
  await request(app).get(`/api/franchise/${owner.id}`).set('Authorization', `Bearer ${diner.token}`).expect(200, []);
  await request(app).get(`/api/franchise/${diner.id}`).set('Authorization', `Bearer ${diner.token}`).expect(200, []);

  await request(app).delete(`${storePath}/${store.body.id}`).set('Authorization', `Bearer ${diner.token}`).expect(403);
  await request(app).delete(`${storePath}/${store.body.id}`).set('Authorization', `Bearer ${admin.token}`).expect(200, { message: 'store deleted' });
  expect((await DB.getFranchise({ id: franchise.id })).stores).toEqual([]);
  await request(app).delete(`/api/franchise/${franchise.id}`).set('Authorization', `Bearer ${admin.token}`).expect(200, { message: 'franchise deleted' });
  expect(await DB.getFranchises(undefined, 0, 10, franchise.name)).toEqual([[], false]);
});

test('persists orders, isolates diner history, and handles factory failures', async () => {
  const franchise = await createFranchise();
  const store = await DB.createStore(franchise.id, { name: 'Order store' });
  const item = { title: `Pizza-${randomUUID()}`, description: 'Test pizza', image: 'test.png', price: 0.01 };
  const menu = await request(app).put('/api/order/menu').set('Authorization', `Bearer ${admin.token}`).send(item).expect(200);
  const savedItem = menu.body.find((entry) => entry.title === item.title);
  expect(savedItem).toMatchObject(item);
  menuIds.push(savedItem.id);
  const order = { franchiseId: franchise.id, storeId: store.id, items: [{ menuId: savedItem.id, description: item.description, price: item.price }] };
  const factory = jest.spyOn(global, 'fetch').mockResolvedValue({ ok: true, json: async () => ({ jwt: 'test-factory-result', reportUrl: 'https://example.test/report' }) });
  await request(app).post('/api/order').send(order).expect(401);
  const response = await request(app).post('/api/order').set('Authorization', `Bearer ${diner.token}`).send(order).expect(200);
  expect(response.body).toMatchObject({ order: { ...order, id: expect.any(Number) }, jwt: 'test-factory-result', followLinkToEndChaos: 'https://example.test/report' });
  // Inspect only the payload; factory authorization values must never appear in assertions.
  const payload = JSON.parse(factory.mock.calls[0][1].body);
  expect(payload).toMatchObject({ diner: { id: diner.id, email: diner.email }, order: { id: response.body.order.id } });
  const history = await request(app).get('/api/order').set('Authorization', `Bearer ${diner.token}`).expect(200);
  expect(history.body).toMatchObject({ dinerId: diner.id, orders: [expect.objectContaining({ id: response.body.order.id, items: [expect.objectContaining(order.items[0])] })] });
  const otherHistory = await request(app).get('/api/order').set('Authorization', `Bearer ${owner.token}`).expect(200);
  expect(otherHistory.body.orders).toEqual([]);
  const revenue = await DB.getFranchise({ id: franchise.id });
  expect(revenue.stores[0].totalRevenue).toBe(item.price);

  factory.mockResolvedValueOnce({ ok: false, json: async () => ({ reportUrl: 'https://example.test/failure' }) });
  await request(app).post('/api/order').set('Authorization', `Bearer ${diner.token}`).send(order)
    .expect(500, { message: 'Failed to fulfill order at factory', followLinkToEndChaos: 'https://example.test/failure' });
  factory.mockRejectedValueOnce(new Error('Factory unavailable'));
  const unavailable = await request(app).post('/api/order').set('Authorization', `Bearer ${diner.token}`).send(order).expect(500);
  expect(unavailable.body.message).toBe('Factory unavailable');
  const invalid = await request(app).post('/api/order').set('Authorization', `Bearer ${diner.token}`)
    .send({ ...order, items: [{ ...order.items[0], menuId: -1 }] }).expect(500);
  expect(invalid.body.message).toBe('No ID found');
  expect(factory).toHaveBeenCalledTimes(3);
});
