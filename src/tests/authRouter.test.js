const request = require("supertest");
const app = require("../service");
const { DB } = require("../database/database");
const { randomUUID } = require("node:crypto");

function randomName() {
  return randomUUID();
}

const testUser = { name: "pizza diner", email: "reg@test.com", password: randomUUID() };
let testUserAuthToken;
let userId;

beforeAll(async () => {
  testUser.email = randomName() + "@test.com";
  const registerRes = await request(app).post("/api/auth").send(testUser).expect(200);
  userId = registerRes.body.user.id;
  testUserAuthToken = registerRes.body.token;
  expectValidJwt(testUserAuthToken);
});

afterAll(async () => {
  if (!userId) return;
  const connection = await DB.getConnection();
  try {
    await connection.execute('DELETE FROM auth WHERE userId=?', [userId]);
    await connection.execute('DELETE FROM userRole WHERE userId=?', [userId]);
    await connection.execute('DELETE FROM user WHERE id=?', [userId]);
  } finally {
    await connection.end();
  }
});

test("login", async () => {
  const loginRes = await request(app).put("/api/auth").send(testUser);
  expect(loginRes.status).toBe(200);
  expectValidJwt(loginRes.body.token);

  const expectedUser = { ...testUser, roles: [{ role: "diner" }] };
  delete expectedUser.password;
  expect(loginRes.body.user).toMatchObject(expectedUser);
});

test("get menu as a registered user", async () => {
  const menuRes = await request(app)
    .get("/api/order/menu")
    .set("Authorization", `Bearer ${testUserAuthToken}`);

  expect(menuRes.status).toBe(200);
  expect(Array.isArray(menuRes.body)).toBe(true);
});

function expectValidJwt(potentialJwt) {
  expect(potentialJwt).toMatch(
    /^[a-zA-Z0-9\-_]*\.[a-zA-Z0-9\-_]*\.[a-zA-Z0-9\-_]*$/,
  );
}
