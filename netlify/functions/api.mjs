import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

/* TripMate 云端后端（Netlify Functions v2 + Netlify Blobs）
   存储：
   - u:{sha256(账号)}  用户记录 {id,name,email,username,salt,hash,role,createdAt}
   - u:{sha256(用户名)} = {ref:邮箱键}  用户名别名
   - t:{token}          会话令牌 {userId,createdAt}
   - d:{userId}         用户数据集 {data:{trips,expenses,locations,photos,reminders},updatedAt}
   - p:{userId}:{photoId} 照片 {dataUrl}
*/

const json = (body, status = 200, headers = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers },
  });

const sha = (s) => crypto.createHash("sha256").update(String(s)).digest("hex");
const newToken = () => crypto.randomBytes(24).toString("hex");

/* Netlify 部署时注入的 Blobs 令牌只有 15 分钟有效期且不会自动刷新（CLI 手工部署的已知限制）。
   解决：站点环境变量里配置长期令牌（NETLIFY_BLOBS_FALLBACK_TOKEN，来自 netlify login 的 OAuth 令牌），
   存在时优先通过 api.netlify.com 的 Blobs 接口访问，不再依赖会过期的注入令牌。 */
const SITE_ID = "0e636af7-1c8e-49c7-ac76-a1b68419af00";
let _store = null;
let _storeToken = null;
function ensureCredentials() {
  const fallback = process.env.NETLIFY_BLOBS_FALLBACK_TOKEN;
  if (fallback) {
    if (_store && _storeToken === fallback) return;
    globalThis.netlifyBlobsContext = { apiURL: "https://api.netlify.com", siteID: SITE_ID, token: fallback };
    _store = null;
    _storeToken = fallback;
  }
}
function store() {
  ensureCredentials();
  if (!_store) _store = getStore({ name: "tripmate", consistency: "strong" });
  return _store;
}
const getJSON = async (k) => store().get(k, { type: "json" });
const putJSON = (k, v) => store().setJSON(k, v);
const del = (k) => store().delete(k);
async function listKeys(prefix) {
  const keys = [];
  let res = await store().list({ prefix });
  res.blobs.forEach((b) => keys.push(b.key));
  while (res.nextCursor) {
    res = await store().list({ prefix, cursor: res.nextCursor });
    res.blobs.forEach((b) => keys.push(b.key));
  }
  return keys;
}

const TYPE_KEYS = ["trips", "expenses", "locations", "photos", "reminders"];

function validDataset(d) {
  if (!d || typeof d !== "object") return false;
  for (const k of TYPE_KEYS) if (d[k] !== undefined && !Array.isArray(d[k])) return false;
  return true;
}
function normalizeDataset(d) {
  const out = {};
  for (const k of TYPE_KEYS) out[k] = Array.isArray(d[k]) ? d[k] : [];
  return out;
}
/* 普通用户不可修改/删除已同步的记录，只能新增（notified 为系统字段，不计入比较） */
function firstChange(oldD, newD) {
  for (const k of TYPE_KEYS) {
    const oldMap = new Map((oldD?.[k] || []).map((r) => [r.id, JSON.stringify({ ...r, notified: undefined })]));
    const newIds = new Set((newD[k] || []).map((r) => r.id));
    for (const [id, snap] of oldMap) {
      if (!newIds.has(id)) return "删除了已有记录（" + id + "）";
      const rec = (newD[k] || []).find((r) => r.id === id);
      if (JSON.stringify({ ...rec, notified: undefined }) !== snap) return "修改了已有记录（" + id + "）";
    }
  }
  return null;
}

async function authUser(req) {
  const m = (req.headers.get("authorization") || "").match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  const token = m[1].trim();
  const t = await getJSON("t:" + token);
  if (!t || !t.userId || !t.key) return null;
  const u = await getJSON("u:" + t.key);
  if (!u || u.ref) return null;
  return { token: token, userId: t.userId, role: u.role || "user", user: u };
}

async function findUser(account) {
  const key = sha(String(account || "").trim().toLowerCase());
  let u = await getJSON("u:" + key);
  if (u && u.ref) u = await getJSON("u:" + u.ref);
  return u || null;
}

/* ============ 入口 ============ */
export const config = { path: "/api/*" };

export default async (req) => {
  const url = new URL(req.url);
  const path = url.pathname.replace(/\/+$/, "");
  try {
    return await route(req, path, url);
  } catch (e) {
    return json({ error: String(e && e.message ? e.message : e) }, 500);
  }
};

async function route(req, path, url) {
  const method = req.method.toUpperCase();

  /* ---- 一次性初始化管理员（已有管理员后自动失效） ---- */
  if (path === "/api/setup" && method === "POST") {
    const body = await req.json().catch(() => ({}));
    const username = String(body.username || "admin").trim().toLowerCase();
    const password = String(body.password || "");
    if (password.length < 8) return json({ error: "初始密码至少 8 位" }, 400);
    const exists = await findUser(username);
    if (exists) return json({ error: "管理员已初始化，本接口已失效" }, 403);
    const salt = crypto.randomBytes(12).toString("hex");
    const u = {
      id: crypto.randomUUID(),
      name: String(body.name || "管理员").trim(),
      email: String(body.email || username + "@tripmate.local").toLowerCase(),
      username,
      salt,
      hash: sha(salt + "::" + password),
      role: "admin",
      createdAt: Date.now(),
    };
    await putJSON("u:" + sha(u.email), u);
    await putJSON("u:" + sha(username), { ref: sha(u.email) });
    return json({ ok: true, userId: u.id });
  }

  /* ---- 登录第一步：取盐 ---- */
  if (path === "/api/salt" && method === "POST") {
    const body = await req.json().catch(() => ({}));
    const u = await findUser(body.account);
    if (!u) return json({ error: "账号不存在，请先注册" }, 404);
    return json({ salt: u.salt, userId: u.id, name: u.name, role: u.role || "user" });
  }

  /* ---- 注册（普通用户自助，或老本地账号迁移） ---- */
  if (path === "/api/register" && method === "POST") {
    const body = await req.json().catch(() => ({}));
    const email = String(body.email || "").trim().toLowerCase();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json({ error: "邮箱格式不正确" }, 400);
    if (!body.salt || !body.hash) return json({ error: "缺少凭据" }, 400);
    if (await findUser(email)) return json({ error: "该邮箱已注册，请直接登录" }, 409);
    const u = {
      id: String(body.userId || crypto.randomUUID()),
      name: String(body.name || "用户").trim().slice(0, 40),
      email,
      salt: String(body.salt),
      hash: String(body.hash),
      role: "user",
      createdAt: Date.now(),
    };
    const token = newToken();
    await putJSON("u:" + sha(email), u);
    await putJSON("t:" + token, { userId: u.id, key: sha(u.email), createdAt: Date.now() });
    return json({ token, userId: u.id, name: u.name, role: u.role });
  }

  /* ---- 登录第二步：校验 ---- */
  if (path === "/api/login" && method === "POST") {
    const body = await req.json().catch(() => ({}));
    const u = await findUser(body.account);
    if (!u) return json({ error: "账号不存在，请先注册" }, 404);
    if (String(u.hash) !== String(body.hash)) return json({ error: "密码不正确" }, 401);
    const token = newToken();
    await putJSON("t:" + token, { userId: u.id, key: sha(u.email), createdAt: Date.now() });
    return json({ token, userId: u.id, name: u.name, email: u.email, role: u.role || "user" });
  }

  /* ---- 以下接口需要登录 ---- */
  const auth = await authUser(req);
  if (!auth) return json({ error: "请先登录" }, 401);

  if (path === "/api/data" && method === "GET") {
    const d = await getJSON("d:" + auth.userId);
    return json(d || { data: null, updatedAt: null });
  }

  if (path === "/api/data" && method === "PUT") {
    const body = await req.json().catch(() => ({}));
    if (!validDataset(body.data)) return json({ error: "数据格式不正确" }, 400);
    const nd = normalizeDataset(body.data);
    if ((auth.role || "user") !== "admin") {
      const old = await getJSON("d:" + auth.userId);
      if (old && old.data) {
        const bad = firstChange(old.data, nd);
        if (bad) return json({ error: "普通用户不能修改或删除已同步的记录，请联系管理员处理：" + bad }, 403);
      }
    }
    const rec = { data: nd, updatedAt: Date.now() };
    await putJSON("d:" + auth.userId, rec);
    return json({ updatedAt: rec.updatedAt });
  }

  /* ---- 照片（大对象单独存；管理员可带 ?u= 代管他人照片） ---- */
  const pm = path.match(/^\/api\/photo\/([A-Za-z0-9_-]+)$/);
  if (pm) {
    const photoId = pm[1];
    let owner = auth.userId;
    if (url.searchParams.get("u")) {
      if (auth.role !== "admin") return json({ error: "需要管理员权限" }, 403);
      owner = url.searchParams.get("u");
    }
    const key = "p:" + owner + ":" + photoId;
    if (method === "GET") {
      const p = await getJSON(key);
      if (!p) return json({ error: "照片不存在" }, 404);
      return json(p);
    }
    if (method === "PUT") {
      const body = await req.json().catch(() => ({}));
      const dUrl = String(body.dataUrl || "");
      if (!/^data:image\/(jpeg|png|webp);base64,/.test(dUrl)) return json({ error: "仅支持图片数据" }, 400);
      if (dUrl.length > 5 * 1024 * 1024) return json({ error: "照片过大" }, 413);
      if ((auth.role || "user") !== "admin") {
        const exists = await store().get(key);
        if (exists) return json({ error: "普通用户不能修改已同步的照片" }, 403);
      }
      await putJSON(key, { dataUrl: dUrl });
      return json({ ok: true });
    }
    if (method === "DELETE") {
      if ((auth.role || "user") !== "admin") return json({ error: "普通用户不能删除已同步的照片，请联系管理员" }, 403);
      await del(key);
      return json({ ok: true });
    }
  }

  /* ---- 管理员接口 ---- */
  if (path.startsWith("/api/admin/")) {
    if (auth.role !== "admin") return json({ error: "需要管理员权限" }, 403);

    if (path === "/api/admin/users" && method === "GET") {
      const users = [];
      const blobKeys = await listKeys("u:");
      for (const bkey of blobKeys) {
        const u = await getJSON(bkey);
        if (!u || u.ref) continue;
        const d = await getJSON("d:" + u.id);
        const data = d && d.data ? d.data : null;
        users.push({
          id: u.id, name: u.name, email: u.email, username: u.username || null,
          role: u.role || "user", createdAt: u.createdAt,
          counts: data
            ? { trips: (data.trips || []).length, expenses: (data.expenses || []).length, locations: (data.locations || []).length, photos: (data.photos || []).length, reminders: (data.reminders || []).length }
            : null,
          updatedAt: d ? d.updatedAt : null,
        });
      }
      users.sort((a, b) => (a.createdAt || 0) - (b.createdAt || 0));
      return json({ users });
    }

    if (path === "/api/admin/users" && method === "POST") {
      const body = await req.json().catch(() => ({}));
      const email = String(body.email || "").trim().toLowerCase();
      const username = String(body.username || "").trim().toLowerCase();
      if (!email && !username) return json({ error: "请填写邮箱或用户名" }, 400);
      if (email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json({ error: "邮箱格式不正确" }, 400);
      const password = String(body.password || "");
      if (password.length < 8) return json({ error: "初始密码至少 8 位" }, 400);
      if (email && (await findUser(email))) return json({ error: "该邮箱已被使用" }, 409);
      if (username && (await findUser(username))) return json({ error: "该用户名已被使用" }, 409);
      const salt = crypto.randomBytes(12).toString("hex");
      const u = {
        id: crypto.randomUUID(),
        name: String(body.name || username || email.split("@")[0]).trim().slice(0, 40),
        email: email || username + "@tripmate.local",
        username: username || null,
        salt,
        hash: sha(salt + "::" + password),
        role: body.role === "admin" ? "admin" : "user",
        createdAt: Date.now(),
      };
      await putJSON("u:" + sha(u.email), u);
      if (username) await putJSON("u:" + sha(username), { ref: sha(u.email) });
      return json({ ok: true, userId: u.id });
    }

    const um = path.match(/^\/api\/admin\/users\/([A-Za-z0-9_-]+)$/);
    if (um) {
      const uid = um[1];
      const tKeys = await listKeys("u:");
      let tu = null;
      for (const bkey of tKeys) {
        const cand = await getJSON(bkey);
        if (cand && !cand.ref && cand.id === uid) { tu = { key: bkey, u: cand }; break; }
      }
      if (!tu) return json({ error: "用户不存在" }, 404);
      if (method === "PUT") {
        const body = await req.json().catch(() => ({}));
        if (body.name) tu.u.name = String(body.name).trim().slice(0, 40);
        if (body.role) tu.u.role = body.role === "admin" ? "admin" : "user";
        if (body.password) {
          if (String(body.password).length < 8) return json({ error: "新密码至少 8 位" }, 400);
          tu.u.salt = crypto.randomBytes(12).toString("hex");
          tu.u.hash = sha(tu.u.salt + "::" + String(body.password));
        }
        await putJSON(tu.key, tu.u);
        return json({ ok: true });
      }
      if (method === "DELETE") {
        if (uid === auth.userId) return json({ error: "不能删除自己的账号" }, 400);
        await del(tu.key);
        if (tu.u.username) await del("u:" + sha(tu.u.username));
        const d = await getJSON("d:" + uid);
        await del("d:" + uid);
        if (d && d.data && Array.isArray(d.data.photos)) {
          for (const p of d.data.photos) { try { await del("p:" + uid + ":" + p.id); } catch (e) {} }
        }
        return json({ ok: true });
      }
    }

    /* 代管数据：管理员查看/修改任意用户数据集 */
    const dm = path.match(/^\/api\/admin\/data\/([A-Za-z0-9_-]+)$/);
    if (dm) {
      const uid = dm[1];
      if (method === "GET") {
        const d = await getJSON("d:" + uid);
        return json(d || { data: null, updatedAt: null });
      }
      if (method === "PUT") {
        const body = await req.json().catch(() => ({}));
        if (!validDataset(body.data)) return json({ error: "数据格式不正确" }, 400);
        const rec = { data: normalizeDataset(body.data), updatedAt: Date.now() };
        await putJSON("d:" + uid, rec);
        return json({ updatedAt: rec.updatedAt });
      }
    }
  }

  return json({ error: "接口不存在" }, 404);
}
