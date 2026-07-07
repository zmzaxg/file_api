import { createPool } from "mysql2/promise";

let PROXY_POOL_MAP = new Map();

async function getMysqlPool(env, host, port, user, password, database) {
  const poolKey = `${host}:${port}:${database}`;
  if (PROXY_POOL_MAP.has(poolKey)) return PROXY_POOL_MAP.get(poolKey);
  const pool = createPool({
    host,
    port: Number(port),
    user,
    password,
    database,
    connectionLimit: 2,
    disableEval: true,
    ssl: { rejectUnauthorized: false },
    stream: env.HYPERDRIVE.connect()
  });
  PROXY_POOL_MAP.set(poolKey, pool);
  return pool;
}

async function getIndexPool(env) {
  return getMysqlPool(
    env,
    env.INDEX_DB_HOST,
    env.INDEX_DB_PORT,
    env.INDEX_DB_USER,
    env.INDEX_DB_PASS,
    env.INDEX_DB_NAME
  );
}

function randomStr(len = 32) {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let str = "";
  for (let i = 0; i < len; i++) str += chars[Math.floor(Math.random() * chars.length)];
  return str;
}
function createToken(uid, username, secret) {
  const payload = { uid, username, exp: Date.now() + 7 * 86400 * 1000 };
  return btoa(JSON.stringify(payload)) + "." + btoa(secret);
}
function verifyToken(token, secret) {
  try {
    const [pay, sign] = token.split(".");
    if (btoa(secret) !== sign) return null;
    const data = JSON.parse(atob(pay));
    if (data.exp < Date.now()) return null;
    return data;
  } catch { return null; }
}

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type,Authorization"
};
function resp(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" }
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const JWT_SECRET = env.JWT_SECRET;

    if (request.method === "OPTIONS") return new Response("", { headers: corsHeaders });

    // 注册
    if (path === "/api/register" && request.method === "POST") {
      const { username, password } = await request.json();
      const indexPool = await getIndexPool(env);
      const [dbList] = await indexPool.query("SELECT * FROM db_list WHERE status=1 AND used_size_mb < max_size_mb LIMIT 1");
      if (dbList.length === 0) return resp({ code: -1, msg: "暂无空闲数据库" }, 400);
      const sub = dbList[0];
      const subPool = await getMysqlPool(env, sub.db_host, sub.db_port, sub.db_user, sub.db_pass, sub.db_name);
      try {
        await subPool.query("INSERT INTO user_info(username,password) VALUES (?,?)", [username, btoa(password)]);
      } catch {
        return resp({ code: -2, msg: "账号已存在" }, 400);
      }
      const [user] = await subPool.query("SELECT uid FROM user_info WHERE username=?", [username]);
      await indexPool.query("INSERT INTO user_db_bind(uid,username,db_id) VALUES (?,?,?)", [user[0].uid, username, sub.id]);
      const token = createToken(user[0].uid, username, JWT_SECRET);
      return resp({ code: 0, data: { token, uid: user[0].uid, db_id: sub.id } });
    }

    // 登录
    if (path === "/api/login" && request.method === "POST") {
      const { username, password } = await request.json();
      const indexPool = await getIndexPool(env);
      const [bind] = await indexPool.query("SELECT db_id FROM user_db_bind WHERE username=?", [username]);
      if (bind.length === 0) return resp({ code: -1, msg: "账号不存在" }, 400);
      const [dbInfo] = await indexPool.query("SELECT * FROM db_list WHERE id=?", [bind[0].db_id]);
      const subPool = await getMysqlPool(env, dbInfo[0].db_host, dbInfo[0].db_port, dbInfo[0].db_user, dbInfo[0].db_pass, dbInfo[0].db_name);
      const [user] = await subPool.query("SELECT uid,password FROM user_info WHERE username=?", [username]);
      if (user.length === 0 || atob(user[0].password) !== password) return resp({ code: -2, msg: "密码错误" }, 400);
      const token = createToken(user[0].uid, username, JWT_SECRET);
      return resp({ code: 0, data: { token, uid: user[0].uid, db_id: bind[0].db_id } });
    }

    // 保存文件
    if (path === "/api/file/save" && request.method === "POST") {
      const token = request.headers.get("Authorization")?.replace("Bearer ", "");
      const user = verifyToken(token, JWT_SECRET);
      if (!user) return resp({ code: -1, msg: "未登录" }, 401);
      const { name, size, chunkSize, taskId, chunks } = await request.json();
      const indexPool = await getIndexPool(env);
      const [bind] = await indexPool.query("SELECT db_id FROM user_db_bind WHERE username=?", [user.username]);
      const [dbInfo] = await indexPool.query("SELECT * FROM db_list WHERE id=?", [bind[0].db_id]);
      const subPool = await getMysqlPool(env, dbInfo[0].db_host, dbInfo[0].db_port, dbInfo[0].db_user, dbInfo[0].db_pass, dbInfo[0].db_name);
      await subPool.query(`INSERT INTO user_file(uid,file_name,file_size,chunk_size,task_id,chunks_json,folder_path) VALUES (?,?,?,?,?,?,?)`,
        [user.uid, name, size, chunkSize, taskId, JSON.stringify(chunks), "/"]);
      await indexPool.query("UPDATE db_list SET used_size_mb = used_size_mb + ? WHERE id=?", [Number((size / 1024 / 1024).toFixed(4)), bind[0].db_id]);
      return resp({ code: 0, msg: "保存成功" });
    }

    // 获取文件列表
    if (path === "/api/file/list" && request.method === "GET") {
      const token = request.headers.get("Authorization")?.replace("Bearer ", "");
      const user = verifyToken(token, JWT_SECRET);
      if (!user) return resp({ code: -1, msg: "未登录" }, 401);
      const indexPool = await getIndexPool(env);
      const [bind] = await indexPool.query("SELECT db_id FROM user_db_bind WHERE username=?", [user.username]);
      const [dbInfo] = await indexPool.query("SELECT * FROM db_list WHERE id=?", [bind[0].db_id]);
      const subPool = await getMysqlPool(env, dbInfo[0].db_host, dbInfo[0].db_port, dbInfo[0].db_user, dbInfo[0].db_pass, dbInfo[0].db_name);
      const [files] = await subPool.query("SELECT * FROM user_file WHERE uid=?", [user.uid]);
      return resp({ code: 0, data: files });
    }

    // 删除文件
    if (path === "/api/file/del" && request.method === "POST") {
      const token = request.headers.get("Authorization")?.replace("Bearer ", "");
      const user = verifyToken(token, JWT_SECRET);
      if (!user) return resp({ code: -1, msg: "未登录" }, 401);
      const { fid, size } = await request.json();
      const indexPool = await getIndexPool(env);
      const [bind] = await indexPool.query("SELECT db_id FROM user_db_bind WHERE username=?", [user.username]);
      const [dbInfo] = await indexPool.query("SELECT * FROM db_list WHERE id=?", [bind[0].db_id]);
      const subPool = await getMysqlPool(env, dbInfo[0].db_host, dbInfo[0].db_port, dbInfo[0].db_user, dbInfo[0].db_pass, dbInfo[0].db_name);
      await subPool.query("DELETE FROM user_file WHERE fid=? AND uid=?", [fid, user.uid]);
      await indexPool.query("UPDATE db_list SET used_size_mb = used_size_mb - ? WHERE id=?", [Number((size / 1024 / 1024).toFixed(4)), bind[0].db_id]);
      return resp({ code: 0, msg: "删除成功" });
    }

    // 创建分享
    if (path === "/api/share/create" && request.method === "POST") {
      const token = request.headers.get("Authorization")?.replace("Bearer ", "");
      const user = verifyToken(token, JWT_SECRET);
      if (!user) return resp({ code: -1, msg: "未登录" }, 401);
      const { fid } = await request.json();
      const shareKey = randomStr(24);
      const indexPool = await getIndexPool(env);
      const [bind] = await indexPool.query("SELECT db_id FROM user_db_bind WHERE username=?", [user.username]);
      const [dbInfo] = await indexPool.query("SELECT * FROM db_list WHERE id=?", [bind[0].db_id]);
      const subPool = await getMysqlPool(env, dbInfo[0].db_host, dbInfo[0].db_port, dbInfo[0].db_user, dbInfo[0].db_pass, dbInfo[0].db_name);
      await subPool.query("INSERT INTO share_link(sid,uid,target_type,target_id) VALUES (?,?,1,?)", [shareKey, user.uid, fid]);
      return resp({ code: 0, data: { shareUrl: `${url.origin}/api/share/get?key=${shareKey}` } });
    }

    // 读取分享
    if (path === "/api/share/get") {
      const key = url.searchParams.get("key");
      const indexPool = await getIndexPool(env);
      const [shareRes] = await indexPool.query("SELECT sl.*,ub.db_id FROM share_link sl LEFT JOIN user_db_bind ub ON sl.uid=ub.uid WHERE sl.sid=?", [key]);
      if (shareRes.length === 0) return resp({ code: -1, msg: "分享不存在" }, 404);
      const share = shareRes[0];
      const [dbInfo] = await indexPool.query("SELECT * FROM db_list WHERE id=?", [share.db_id]);
      const subPool = await getMysqlPool(env, dbInfo[0].db_host, dbInfo[0].db_port, dbInfo[0].db_user, dbInfo[0].db_pass, dbInfo[0].db_name);
      const [file] = await subPool.query("SELECT * FROM user_file WHERE fid=?", [share.target_id]);
      return resp({ code: 0, data: file[0] });
    }

    return resp({ code: -99, msg: "接口不存在" }, 404);
  }
};