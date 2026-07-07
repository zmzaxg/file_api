import { createPool } from "mysql2/promise";

// ========== 1. 密钥配置（后台环境变量填写，不要写死在这里） ==========
let INDEX_POOL;
async function getIndexPool() {
  if (!INDEX_POOL) {
    INDEX_POOL = createPool({
      host: ENV.INDEX_DB_HOST,
      port: ENV.INDEX_DB_PORT || 3306,
      user: ENV.INDEX_DB_USER,
      password: ENV.INDEX_DB_PASS,
      database: ENV.INDEX_DB_NAME,
      connectionLimit: 5,
      disableEval: true,
      ssl: { rejectUnauthorized: false }
    });
  }
  return INDEX_POOL;
}

// 根据子库配置动态创建连接池
async function getSubDbPool(dbConf) {
  return createPool({
    host: dbConf.db_host,
    port: dbConf.db_port || 3306,
    user: dbConf.db_user,
    password: dbConf.db_pass,
    database: dbConf.db_name,
    connectionLimit: 2,
    disableEval: true,
    ssl: { rejectUnauthorized: false }
  });
}

// JWT简单鉴权密钥，环境变量配置
const JWT_SECRET = ENV.JWT_SECRET;

// ========== 工具函数 ==========
// 生成随机字符串
function randomStr(len = 32) {
  const c = "abcdefghijklmnopqrstuvwxyz0123456789";
  let s = "";
  for (let i = 0; i < len; i++) s += c[Math.floor(Math.random() * c.length)];
  return s;
}

// 简易JWT（Workers无第三方包，手写极简版）
function createToken(uid, username) {
  const payload = { uid, username, exp: Date.now() + 86400000 * 7 };
  const raw = btoa(JSON.stringify(payload)) + "." + btoa(JWT_SECRET);
  return raw;
}
function verifyToken(token) {
  try {
    const [pay, sign] = token.split(".");
    if (btoa(JWT_SECRET) !== sign) return null;
    const payload = JSON.parse(atob(pay));
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

// CORS跨域统一处理（允许Pages前端跨域请求）
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type,Authorization"
};

// 统一返回响应
function resp(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" }
  });
}

// ========== 所有API接口逻辑 ==========
export default {
  async fetch(request, env, ctx) {
    globalThis.ENV = env;
    const url = new URL(request.url);
    const path = url.pathname;

    // 预检OPTIONS请求直接放行
    if (request.method === "OPTIONS") {
      return new Response("", { headers: corsHeaders });
    }

    // 1. 注册接口 POST /api/register
    if (path === "/api/register" && request.method === "POST") {
      const { username, password } = await request.json();
      const indexPool = await getIndexPool();
      // 1. 查询空闲5M子库
      const [dbList] = await indexPool.query(`
        SELECT * FROM db_list WHERE status=1 AND used_size_mb < max_size_mb LIMIT 1
      `);
      if (dbList.length === 0) return resp({ code: -1, msg: "暂无空闲数据库" }, 400);
      const subDb = dbList[0];
      const subPool = await getSubDbPool(subDb);

      // 2. 创建用户
      const pwdEnc = btoa(password); // 简易加密，生产推荐bcrypt
      try {
        await subPool.query("INSERT INTO user_info(username,password) VALUES (?,?)", [username, pwdEnc]);
      } catch (e) {
        return resp({ code: -2, msg: "账号已存在" }, 400);
      }
      const [userRow] = await subPool.query("SELECT uid FROM user_info WHERE username=?", [username]);
      const uid = userRow[0].uid;

      // 3. 绑定用户与子库到引导库
      await indexPool.query(`
        INSERT INTO user_db_bind(uid,username,db_id) VALUES (?,?,?)
      `, [uid, username, subDb.id]);

      // 4. 返回登录token
      const token = createToken(uid, username);
      return resp({ code: 0, msg: "注册成功", data: { token, uid, db_id: subDb.id } });
    }

    // 2. 登录接口 POST /api/login
    if (path === "/api/login" && request.method === "POST") {
      const { username, password } = await request.json();
      const indexPool = await getIndexPool();
      // 查询用户绑定的子库ID
      const [bindRow] = await indexPool.query("SELECT db_id FROM user_db_bind WHERE username=?", [username]);
      if (bindRow.length === 0) return resp({ code: -1, msg: "账号不存在" }, 400);
      const dbId = bindRow[0].db_id;
      // 获取子库配置
      const [dbRow] = await indexPool.query("SELECT * FROM db_list WHERE id=?", [dbId]);
      const subDb = dbRow[0];
      const subPool = await getSubDbPool(subDb);
      // 校验密码
      const [userRow] = await subPool.query("SELECT uid,password FROM user_info WHERE username=?", [username]);
      if (userRow.length === 0 || atob(userRow[0].password) !== password) {
        return resp({ code: -2, msg: "密码错误" }, 400);
      }
      const token = createToken(userRow[0].uid, username);
      return resp({ code: 0, msg: "登录成功", data: { token, uid: userRow[0].uid, db_id: dbId } });
    }

    // 3. 上传完成保存文件元数据 POST /api/file/save
    if (path === "/api/file/save" && request.method === "POST") {
      const token = request.headers.get("Authorization")?.replace("Bearer ", "");
      const userInfo = verifyToken(token);
      if (!userInfo) return resp({ code: -1, msg: "未登录或token过期" }, 401);
      const { name, size, chunkSize, taskId, chunks } = await request.json();
      const indexPool = await getIndexPool();
      const [bindRow] = await indexPool.query("SELECT db_id FROM user_db_bind WHERE username=?", [userInfo.username]);
      const [dbRow] = await indexPool.query("SELECT * FROM db_list WHERE id=?", [bindRow[0].db_id]);
      const subDb = dbRow[0];
      const subPool = await getSubDbPool(subDb);
      // 插入文件记录
      await subPool.query(`
        INSERT INTO user_file(uid,file_name,file_size,chunk_size,task_id,chunks_json,folder_path)
        VALUES (?,?,?,?,?,?,?)
      `, [userInfo.uid, name, size, chunkSize, taskId, JSON.stringify(chunks), "/"]);
      // 更新子库占用容量
      await indexPool.query(`
        UPDATE db_list SET used_size_mb = used_size_mb + ? WHERE id=?
      `, [(size / 1024 / 1024), bindRow[0].db_id]);
      return resp({ code: 0, msg: "文件保存成功" });
    }

    // 4. 获取用户全部文件 GET /api/file/list
    if (path === "/api/file/list" && request.method === "GET") {
      const token = request.headers.get("Authorization")?.replace("Bearer ", "");
      const userInfo = verifyToken(token);
      if (!userInfo) return resp({ code: -1, msg: "未登录" }, 401);
      const indexPool = await getIndexPool();
      const [bindRow] = await indexPool.query("SELECT db_id FROM user_db_bind WHERE username=?", [userInfo.username]);
      const [dbRow] = await indexPool.query("SELECT * FROM db_list WHERE id=?", [bindRow[0].db_id]);
      const subDb = dbRow[0];
      const subPool = await getSubDbPool(subDb);
      const [files] = await subPool.query("SELECT * FROM user_file WHERE uid=?", [userInfo.uid]);
      return resp({ code: 0, data: files });
    }

    // 5. 删除文件 POST /api/file/del
    if (path === "/api/file/del" && request.method === "POST") {
      const token = request.headers.get("Authorization")?.replace("Bearer ", "");
      const userInfo = verifyToken(token);
      if (!userInfo) return resp({ code: -1, msg: "未登录" }, 401);
      const { fid, size } = await request.json();
      const indexPool = await getIndexPool();
      const [bindRow] = await indexPool.query("SELECT db_id FROM user_db_bind WHERE username=?", [userInfo.username]);
      const dbId = bindRow[0].db_id;
      const [dbRow] = await indexPool.query("SELECT * FROM db_list WHERE id=?", [dbId]);
      const subDb = dbRow[0];
      const subPool = await getSubDbPool(subDb);
      await subPool.query("DELETE FROM user_file WHERE fid=? AND uid=?", [fid, userInfo.uid]);
      // 扣减容量
      await indexPool.query(`
        UPDATE db_list SET used_size_mb = used_size_mb - ? WHERE id=?
      `, [(size / 1024 / 1024), dbId]);
      return resp({ code: 0, msg: "删除成功" });
    }

    // 6. 创建分享链接 POST /api/share/create
    if (path === "/api/share/create" && request.method === "POST") {
      const token = request.headers.get("Authorization")?.replace("Bearer ", "");
      const userInfo = verifyToken(token);
      if (!userInfo) return resp({ code: -1, msg: "未登录" }, 401);
      const { fid } = await request.json();
      const shareKey = randomStr(24);
      const indexPool = await getIndexPool();
      const [bindRow] = await indexPool.query("SELECT db_id FROM user_db_bind WHERE username=?", [userInfo.username]);
      const [dbRow] = await indexPool.query("SELECT * FROM db_list WHERE id=?", [bindRow[0].db_id]);
      const subDb = dbRow[0];
      const subPool = await getSubDbPool(subDb);
      await subPool.query(`
        INSERT INTO share_link(sid,uid,target_type,target_id) VALUES (?,?,1,?)
      `, [shareKey, userInfo.uid, fid]);
      return resp({ code: 0, data: { shareUrl: `${url.origin}/api/share/get?key=${shareKey}` } });
    }

    // 7. 获取分享文件 GET /api/share/get?key=xxx
    if (path === "/api/share/get" && request.method === "GET") {
      const key = url.searchParams.get("key");
      const indexPool = await getIndexPool();
      // 遍历绑定库找到分享所属用户子库
      const [shareAll] = await indexPool.query(`
        SELECT sl.*,ub.db_id FROM share_link sl
        LEFT JOIN user_db_bind ub ON sl.uid = ub.uid
        WHERE sl.sid=?
      `, [key]);
      if (shareAll.length === 0) return resp({ code: -1, msg: "分享不存在或已过期" }, 404);
      const share = shareAll[0];
      const [dbRow] = await indexPool.query("SELECT * FROM db_list WHERE id=?", [share.db_id]);
      const subDb = dbRow[0];
      const subPool = await getSubDbPool(subDb);
      const [file] = await subPool.query("SELECT * FROM user_file WHERE fid=?", [share.target_id]);
      return resp({ code: 0, data: file[0] });
    }

    return resp({ code: -99, msg: "接口不存在" }, 404);
  }
};