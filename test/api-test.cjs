/* TripMate 后端接口自动化测试 */
const crypto = require("crypto");
const BASE = "https://stately-pie-6ebbdc.netlify.app";
const sha = (s) => crypto.createHash("sha256").update(String(s)).digest("hex");
const api = async (method, path, body, token) => {
  const headers = {};
  if (token) headers.Authorization = "Bearer " + token;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const r = await fetch(BASE + path, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  let d = null;
  try { d = await r.json(); } catch (e) {}
  return { status: r.status, data: d };
};
let pass = 0, fail = 0;
const ok = (name, cond, detail) => {
  if (cond) { pass++; console.log("  PASS  " + name); }
  else { fail++; console.log("  FAIL  " + name + (detail ? "  -> " + JSON.stringify(detail) : "")); }
};

(async () => {
  console.log("== 1. 管理员登录流程 ==");
  const salt1 = await api("POST", "/api/salt", { account: "admin" });
  ok("管理员取盐 + role=admin", salt1.status === 200 && salt1.data.role === "admin", salt1.data);
  ok("用户名存的中文昵称正常", salt1.data.name === "管理员", salt1.data.name);
  const hashAdmin = sha(salt1.data.salt + "::admin88888888");
  const login1 = await api("POST", "/api/login", { account: "admin", hash: hashAdmin });
  ok("管理员登录成功", login1.status === 200 && login1.data.token && login1.data.role === "admin", login1.data);
  const adminToken = login1.data.token;
  const wrongPw = await api("POST", "/api/login", { account: "admin", hash: sha(salt1.data.salt + "::wrong-password") });
  ok("错误密码被拒绝(401)", wrongPw.status === 401, wrongPw);

  console.log("== 1.5 管理员昵称修复与旧测试数据清理 ==");
  {
    const lst = await api("GET", "/api/admin/users", undefined, adminToken);
    for (const u of (lst.data.users || [])) {
      const isTest = /@test.local$/.test(u.email || "") || u.username === "lisi";
      if (u.id === login1.data.userId && u.name !== "管理员") {
        await api("PUT", "/api/admin/users/" + u.id, { name: "管理员" }, adminToken);
        console.log("  FIX   admin name fixed");
      } else if (isTest) {
        await api("DELETE", "/api/admin/users/" + u.id, undefined, adminToken);
        console.log("  CLEAN removed old test account " + (u.username || u.email));
      }
    }
  }
  console.log("== 2. 普通用户自助注册 ==");
  const runId = Date.now().toString(36);
  const uEmail = "zhangsan-" + runId + "@test.local", uSalt = "s" + runId;
  const uHash = sha(uSalt + "::zhang123456");
  const reg = await api("POST", "/api/register", { name: "张三", email: uEmail, salt: uSalt, hash: uHash, userId: "u-" + runId });
  ok("注册成功 + 返回token", reg.status === 200 && reg.data.token && reg.data.userId === "u-" + runId, reg.data);
  const dup = await api("POST", "/api/register", { name: "x", email: uEmail, salt: "x", hash: "x" });
  ok("重复邮箱被拒(409)", dup.status === 409, dup);
  const uLogin = await api("POST", "/api/login", { account: uEmail, hash: uHash });
  ok("用户登录成功 role=user", uLogin.status === 200 && uLogin.data.role === "user", uLogin.data);
  const userToken = uLogin.data.token;

  console.log("== 3. 普通用户数据同步（新增允许 / 修改删除禁止） ==");
  const put1 = await api("PUT", "/api/data", { data: {
    trips: [{ id: "t1", userId: "u-" + runId, name: "北京出差", startDate: "2026-09-28" }],
    expenses: [{ id: "e1", userId: "u-" + runId, tripId: "t1", amount: 128, category: "meal", note: "午餐", date: "2026-09-28", createdAt: 1 }],
    locations: [{ id: "l1", userId: "u-" + runId, tripId: "t1", lat: 39.9, lng: 116.4, name: "国贸", note: "客户", ts: 1 }],
    photos: [], reminders: []
  } }, userToken);
  ok("首次保存成功", put1.status === 200, put1);
  const get1 = await api("GET", "/api/data", undefined, userToken);
  ok("读回数据一致", get1.status === 200 && get1.data.data.expenses.length === 1, get1.data);
  // 新增一条（保留原记录）→ 允许
  const put2 = await api("PUT", "/api/data", { data: {
    trips: [{ id: "t1", userId: "u-" + runId, name: "北京出差", startDate: "2026-09-28" }],
    expenses: [
      { id: "e1", userId: "u-" + runId, tripId: "t1", amount: 128, category: "meal", note: "午餐", date: "2026-09-28", createdAt: 1 },
      { id: "e2", userId: "u-" + runId, tripId: "t1", amount: 60, category: "transport", note: "打车", date: "2026-09-28", createdAt: 2 }
    ],
    locations: [{ id: "l1", userId: "u-" + runId, tripId: "t1", lat: 39.9, lng: 116.4, name: "国贸", note: "客户", ts: 1 }],
    photos: [], reminders: []
  } }, userToken);
  ok("用户新增记录允许", put2.status === 200, put2);
  // 修改已有记录 → 拒绝
  const mod = JSON.parse(JSON.stringify(get1.data.data));
  mod.expenses[0].amount = 999;
  const put3 = await api("PUT", "/api/data", { data: mod }, userToken);
  ok("用户修改已有记录被拒(403)", put3.status === 403, put3);
  // 删除已有记录 → 拒绝
  const del = JSON.parse(JSON.stringify(get1.data.data));
  del.expenses.splice(0, 1);
  const put4 = await api("PUT", "/api/data", { data: del }, userToken);
  ok("用户删除已有记录被拒(403)", put4.status === 403, put4);
  // notified 字段变化不应触发拒绝
  const fresh = await api("GET", "/api/data", undefined, userToken);
  const notif = JSON.parse(JSON.stringify(fresh.data.data));
  notif.reminders = [{ id: "r1", userId: "u-" + runId, tripId: "t1", title: "取发票", dueTs: 1, done: false, notified: true }];
  const put5 = await api("PUT", "/api/data", { data: notif }, userToken);
  ok("系统字段(notified)变化不误判", put5.status === 200, put5);

  console.log("== 4. 管理员权限 ==");
  const noAuth = await api("GET", "/api/admin/users");
  ok("未登录访问管理接口被拒(401)", noAuth.status === 401);
  const asUser = await api("GET", "/api/admin/users", undefined, userToken);
  ok("普通用户访问管理接口被拒(403)", asUser.status === 403);
  const list1 = await api("GET", "/api/admin/users", undefined, adminToken);
  ok("管理员列出用户", list1.status === 200 && list1.data.users.length >= 2, list1.data);
  const zhang = list1.data.users.find(u => u.id === "u-" + runId);
  ok("用户列表含记录统计", zhang && zhang.counts && zhang.counts.expenses === 2, zhang && zhang.counts);
  const create1 = await api("POST", "/api/admin/users", { name: "李四", username: "lisi", role: "user", password: "lisi88888888" }, adminToken);
  ok("管理员创建用户成功", create1.status === 200 && create1.data.userId, create1.data);
  const lisiLogin = await api("POST", "/api/login", { account: "lisi", hash: sha((await api("POST", "/api/salt", { account: "lisi" })).data.salt + "::lisi88888888") });
  ok("用户名+密码登录成功", lisiLogin.status === 200 && lisiLogin.data.userId === create1.data.userId, lisiLogin.data);
  const adminEdit = await api("PUT", "/api/admin/data/u-" + runId + "", { data: {
    trips: get1.data.data.trips,
    expenses: [{ id: "e1", userId: "u-" + runId, tripId: "t1", amount: 999, category: "meal", note: "午餐(管理员改)", date: "2026-09-28", createdAt: 1 }],
    locations: get1.data.data.locations,
    photos: [], reminders: get1.data.data.reminders
  } }, adminToken);
  ok("管理员可修改用户数据", adminEdit.status === 200, adminEdit);

  console.log("== 5. 照片云同步 ==");
  const tinyPng = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
  const ph1 = await api("PUT", "/api/photo/ph1", { dataUrl: tinyPng }, userToken);
  ok("用户上传照片成功", ph1.status === 200, ph1);
  const ph2 = await api("PUT", "/api/photo/ph1", { dataUrl: tinyPng }, userToken);
  ok("用户重复上传同一照片被拒(403)", ph2.status === 403, ph2);
  const ph3 = await api("GET", "/api/photo/ph1", undefined, userToken);
  ok("照片读回成功", ph3.status === 200 && ph3.data.dataUrl === tinyPng, ph3.status);
  const ph4 = await api("DELETE", "/api/photo/ph1", undefined, userToken);
  ok("用户删照片被拒(403)", ph4.status === 403, ph4);
  const ph5 = await api("DELETE", "/api/photo/ph1?u=u-" + runId, undefined, adminToken);
  ok("管理员删照片成功", ph5.status === 200, ph5);
  const ph6 = await api("GET", "/api/photo/ph1", undefined, userToken);
  ok("删除后照片404", ph6.status === 404, ph6.status);
  const phAdmin = await api("PUT", "/api/photo/phadm?u=" + runId + "", { dataUrl: tinyPng }, adminToken);
  ok("管理员代用户传照片", phAdmin.status === 200, phAdmin);

  console.log("== 6. 未授权访问 ==");
  const noTok = await api("GET", "/api/data");
  ok("无token读数据被拒(401)", noTok.status === 401);
  const badTok = await api("GET", "/api/data", undefined, "invalid-token-xyz");
  ok("无效token被拒(401)", badTok.status === 401);

  console.log("\n===== 结果: " + pass + " 通过, " + fail + " 失败 =====");
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error("测试脚本异常:", e); process.exit(1); });
