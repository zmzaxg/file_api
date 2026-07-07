import { createPool } from "mysql2/promise";

let PROXY_POOL_MAP = new Map();

// 统一代理创建连接，env由fetch传入，无全局ENV
async function getMysqlPool(env, host, port, user, password, database) {
  const poolKey = `${host}:${port}:${database}`;
  if (PROXY_POOL_MAP.has(poolKey)) {
    return PROXY_POOL_MAP.get(poolKey);
  }
  const pool = createPool({
    host: host,
    port: Number(port),
    user: user,
    password: password,
    database: database,
    connectionLimit: 2,
    disableEval: true,
    ssl: { rejectUnauthorized: false },
    stream: env.HYPERDRIVE.connect()
  });
  PROXY_POOL_MAP.set(poolKey, pool);
  return pool;
}

// 获取引导库连接池
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

// 工具函数
function randomStr(len = 32) {
  const c = "abcdefghijklmnopqrstuvwxyz0123456789";
  let s = "";
  for (let i = 0; i < len; i++) s += c[Math.floor(Math.random() * c.length)];
  return s;
}
function createToken(uid, username, secret) {
  const payload = { uid, username, exp: Date.now() + 86400000 * 7 };
  const raw = btoa(JSON.stringify(payload)) + "." + btoa(secret);
  return raw;
}
function verifyToken(token, secret) {
  try {
    const [pay, sign] = token.split(".");
    if (btoa(secret) !== sign) return null;
    const payload = JSON.parse(atob(pay));
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

// CORS
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
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const JWT_SECRET = env.JWT_SECRET;

    if (request.method === "OPTIONS") return new Response("", { headers: corsHeaders });

    // 注册
    if (path === "/api/register" && request.method === "POST") {
      const { username, password } = await request.json();
      const indexPool = await getIndexPool(env);
      const [dbList] = await indexPool.query(`
        SELECT * FROM db_list WHERE status=1 AND used_size_mb < max_size_mb LIMIT 1
      `);
      if (dbList.length === 0) return resp({ code: -1, msg: "暂无空闲数据库" }, 400);
      const subDbConf = dbList[0];
      const subPool = await getMysqlPool(env,
        subDbConf.db_host,
        subDbConf.db_port,
        subDbConf.db_user,
        subDbConf.db_pass,
        subDbConf.db_name
      );
      const pwdEnc = btoa(password);
      try {
        await subPool.query("INSERT INTO user_info(username,password) VALUES (?,?)", [username, pwdEnc]);
      } catch {
        return resp({ code: -2, msg: "账号已存在" }, 400);
      }
      const [userRow] = await subPool.query("SELECT uid FROM user_info WHERE username=?", [username]);
      const uid = userRow[0].uid;
      await indexPool.query("INSERT INTO user_db_bind(uid,username,db_id) VALUES (?,?,?)", [uid, username, subDbConf.id]);
      const token = createToken(uid, username, JWT_SECRET);
      return resp({ code: 0, data: { token, uid, db_id: subDbConf.id } });
    }

    // 登录
    if (path === "/api/login" && request.method === "POST") {
      const { username, password } = await request.json();
      const indexPool = await getIndexPool(env);
      const [bindRow] = await indexPool.query("SELECT db_id FROM user_db_bind WHERE username=?", [username]);
      if (bindRow.length === 0) return resp({ code: -1, msg: "账号不存在" }, 400);
      const dbId = bindRow[0].db_id;
      const [dbConfRow] = await indexPool.query("SELECT * FROM db_list WHERE id=?", [dbId]);
      if (dbConfRow.length === 0) return resp({ code: -1, msg: "数据库配置丢失" }, 500);
      const subDbConf = dbConfRow[0];
      const subPool = await getMysqlPool(env,
        subDbConf.db_host,
        subDbConf.db_port,
        subDbConf.db_user,
        subDbConf.db_pass,
        subDbConf.db_name
      );
      const [userRow] = await subPool.query("SELECT uid,password FROM user_info WHERE username=?", [username]);
      if (userRow.length === 0 || atob(userRow[0].password) !== password) {
        return resp({ code: -2, msg: "密码错误" }, 400);
      }
      const token = createToken(userRow[0].uid, username, JWT_SECRET);
      return resp({ code: 0, data: { token, uid: userRow[0].uid, db_id: dbId } });
    }

    // 保存文件
    if (path === "/api/file/save" && request.method === "POST") {
      const token = request.headers.get("Authorization")?.replace("Bearer ", "");
      const userInfo = verifyToken(token, JWT_SECRET);
      if (!userInfo) return resp({ code: -1, msg: "未登录" }, 401);
      const { name, size, chunkSize, taskId, chunks } = await request.json();
      const indexPool = await getIndexPool(env);
      const [bindRow] = await indexPool.query("SELECT db_id FROM user_db_bind WHERE username=?", [userInfo.username]);
      const dbId = bindRow[0].db_id;
      const [dbConfRow] = await indexPool.query("SELECT * FROM db_list WHERE id=?", [dbId]);
      const subDbConf = dbConfRow[0];
      const subPool = await getMysqlPool(env,
        subDbConf.db_host,
        subDbConf.db_port,
        subDbConf.db_user,
        subDbConf.db_pass,
        subDbConf.db_name
      );
      await subPool.query(`
        INSERT INTO user_file(uid,file_name,file_size,chunk_size,task_id,chunks_json,folder_path)
        VALUES (?,?,?,?,?,?,?)
      `, [userInfo.uid, name, size, chunkSize, taskId, JSON.stringify(chunks), "/"]);
      const addMb = Number((size / 1024 / 1024).toFixed(4));
      await indexPool.query("UPDATE db_list SET used_size_mb = used_size_mb + ? WHERE id=?", [addMb, dbId]);
      return resp({ code: 0, msg: "文件保存成功" });
    }

    // 获取文件列表
    if (path === "/api/file/list" && request.method === "GET") {
      const token = request.headers.get("Authorization")?.replace("Bearer ", "");
      const userInfo = verifyToken(token, JWT_SECRET);
      if (!userInfo) return resp({ code: -1, msg: "未登录" }, 401);
      const indexPool = await getIndexPool(env);
      const [bindRow] = await indexPool.query("SELECT db_id FROM user_db_bind WHERE username=?", [userInfo.username]);
      const dbId = bindRow[0].db_id;
      const [dbConfRow] = await indexPool.query("SELECT * FROM db_list WHERE id=?", [dbId]);
      const subDbConf = dbConfRow[0];
      const subPool = await getMysqlPool(env,
        subDbConf.db_host,
        subDbConf.db_port,
        subDbConf.db_user,
        subDbConf.db_pass,
        subDbConf.db_name
      );
      const [files] = await subPool.query("SELECT * FROM user_file WHERE uid=?", [userInfo.uid]);
      return resp({ code: 0, data: files });
    }

    // 删除文件
    if (path === "/api/file/del" && request.method === "POST") {
      const token = request.headers.get("Authorization")?.replace("Bearer ", "");
      const userInfo = verifyToken(token, JWT_SECRET);
      if (!userInfo) return resp({ code: -1, msg: "未登录" }, 401);
      const { fid, size } = await request.json();
      const indexPool = await getIndexPool(env);
      const [bindRow] = await indexPool.query("SELECT db_id FROM user_db_bind WHERE username=?", [userInfo.username]);
      const dbId = bindRow[0].db_id;
      const [dbConfRow] = await indexPool.query("SELECT * FROM db_list WHERE id=?", [dbId]);
      const subDbConf = dbConfRow[0];
      const subPool = await getMysqlPool(env,
        subDbConf.db_host,
        subDbConf.db_port,
        subDbConf.db_user,
        subDbConf.db_pass,
        subDbConf.db_name
      );
      await subPool.query("DELETE FROM user_file WHERE fid=? AND uid=?", [fid, userInfo.uid]);
      const subMb = Number((size / 1024 / 1024).toFixed(4));
      await indexPool.query("UPDATE db_list SET used_size_mb = used_size_mb - ? WHERE id=?", [subMb, dbId]);
      return resp({ code: 0, msg: "删除成功" });
    }

    // 创建分享
    if (path === "/api/share/create" && request.method === "POST") {
      const token = request.headers.get("Authorization")?.replace("Bearer ", "");
      const userInfo = verifyToken(token, JWT_SECRET);
      if (!userInfo) return resp({ code: -1, msg: "未登录" }, 401);
      const { fid } = await request.json();
      const shareKey = randomStr(24);
      const indexPool = await getIndexPool(env);
      const [bindRow] = await indexPool.query("SELECT db_id FROM user_db_bind WHERE username=?", [userInfo.username]);
      const dbId = bindRow[0].db_id;
      const [dbConfRow] = await indexPool.query("SELECT * FROM db_list WHERE id=?", [dbId]);
      const subDbConf = dbConfRow[0];
      const subPool = await getMysqlPool(env,
        subDbConf.db_host,
        subDbConf.db_port,
        subDbConf.db_user,
        subDbConf.db_pass,
        subDbConf.db_name
      );
      await subPool.query("INSERT INTO share_link(sid,uid,target_type,target_id) VALUES (?,?,1,?)", [shareKey, userInfo.uid, fid]);
      return resp({ code: 0, data: { shareUrl: `${url.origin}/api/share/get?key=${shareKey}` } });
    }

    // 读取分享
    if (path === "/api/share/get") {
      const key = url.searchParams.get("key");
      const indexPool = await getIndexPool(env);
      const [shareAll] = await indexPool.query(`
        SELECT sl.*,ub.db_id FROM share_link sl
        LEFT JOIN user_db_bind ub ON sl.uid = ub.uid
        WHERE sl.sid=?
      `, [key]);
      if (shareAll.length === 0) return resp({ code: -1, msg: "分享不存在" }, 404);
      const share = shareAll[0];
      const [dbConfRow] = await indexPool.query("SELECT * FROM db_list WHERE id=?", [share.db_id]);
      const subDbConf = dbConfRow[0];
      const subPool = await getMysqlPool(env,
        subDbConf.db_host,
        subDbConf.db_port,
        subDbConf.db_user,
        subDbConf.db_pass,
        subDbConf.db_name
      );
      const [file] = await subPool.query("SELECT * FROM user_file WHERE fid=?", [share.target_id]);
      return resp({ code: 0, data: file[0] });
    }

    return resp({ code: -99, msg: "接口不存在" }, 404);
  }
};