const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
app.disable("x-powered-by");

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"]
    }
  }
}));

app.use(express.json({ limit: "20kb" }));

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const SESSION_SECRET = process.env.SESSION_SECRET || ADMIN_TOKEN;
const KEY_HASH_SALT = process.env.KEY_HASH_SALT || "";
const KEY_ENCRYPTION_SECRET =
  process.env.KEY_ENCRYPTION_SECRET || KEY_HASH_SALT;

const COOKIE_NAME = "aimlock_admin";
const SESSION_DAYS = 30;
const SESSION_MS = SESSION_DAYS * 24 * 60 * 60 * 1000;

if (
  !DATABASE_URL ||
  !KEY_HASH_SALT ||
  !ADMIN_USERNAME ||
  !ADMIN_PASSWORD ||
  !SESSION_SECRET
) {
  console.error(
    "Missing DATABASE_URL, KEY_HASH_SALT, ADMIN_USERNAME, ADMIN_PASSWORD or SESSION_SECRET"
  );
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "false"
    ? false
    : { rejectUnauthorized: false }
});

/* =========================
   SECURITY / HELPERS
========================= */

function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));

  return left.length === right.length &&
    crypto.timingSafeEqual(left, right);
}

function hashKey(key) {
  return crypto.createHmac("sha256", KEY_HASH_SALT)
    .update(key.trim().toUpperCase())
    .digest("hex");
}

function hashDeviceId(deviceId) {
  return crypto.createHmac("sha256", KEY_HASH_SALT)
    .update("device:" + deviceId.trim())
    .digest("hex");
}

function encryptionKey() {
  return crypto.createHash("sha256")
    .update(KEY_ENCRYPTION_SECRET)
    .digest();
}

function encryptKey(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    encryptionKey(),
    iv
  );

  const encrypted = Buffer.concat([
    cipher.update(value, "utf8"),
    cipher.final()
  ]);

  return [
    iv.toString("base64"),
    cipher.getAuthTag().toString("base64"),
    encrypted.toString("base64")
  ].join(".");
}

function decryptKey(value) {
  const [ivText, tagText, encryptedText] = String(value).split(".");

  if (!ivText || !tagText || !encryptedText) {
    throw new Error("Encrypted key is invalid");
  }

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    encryptionKey(),
    Buffer.from(ivText, "base64")
  );

  decipher.setAuthTag(Buffer.from(tagText, "base64"));

  return Buffer.concat([
    decipher.update(Buffer.from(encryptedText, "base64")),
    decipher.final()
  ]).toString("utf8");
}

function makeKey() {
  const raw = crypto.randomBytes(8).toString("hex").toUpperCase();
  return "AIM-" + raw.match(/.{1,4}/g).join("-");
}

function addDuration(start, type, amount) {
  const date = new Date(start);

  if (type === "hours") {
    date.setUTCHours(date.getUTCHours() + amount);
  } else if (type === "days") {
    date.setUTCDate(date.getUTCDate() + amount);
  } else if (type === "weeks") {
    date.setUTCDate(date.getUTCDate() + amount * 7);
  } else if (type === "months" || type === "years") {
    const months = type === "years" ? amount * 12 : amount;
    const originalDay = date.getUTCDate();

    date.setUTCDate(1);
    date.setUTCMonth(date.getUTCMonth() + months);

    const lastDay = new Date(Date.UTC(
      date.getUTCFullYear(),
      date.getUTCMonth() + 1,
      0
    )).getUTCDate();

    date.setUTCDate(Math.min(originalDay, lastDay));
  }

  return date;
}

/* =========================
   COOKIE / SESSION
========================= */

function createSessionCookie(res, username) {
  const payload = Buffer.from(JSON.stringify({
    username,
    exp: Date.now() + SESSION_MS
  })).toString("base64url");

  const signature = crypto.createHmac("sha256", SESSION_SECRET)
    .update(payload)
    .digest("base64url");

  const value = encodeURIComponent(payload + "." + signature);

  const cookie =
    `${COOKIE_NAME}=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_MS / 1000}` +
    (process.env.NODE_ENV === "production" ? "; Secure" : "");

  res.setHeader("Set-Cookie", cookie);
}

function clearSessionCookie(res) {
  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0` +
    (process.env.NODE_ENV === "production" ? "; Secure" : "")
  );
}

/* Cookie parser */
app.use((req, res, next) => {
  req.cookies = {};

  const header = req.headers.cookie || "";

  header.split(";").forEach(part => {
    const index = part.indexOf("=");

    if (index > 0) {
      const name = part.slice(0, index).trim();
      const value = part.slice(index + 1).trim();

      try {
        req.cookies[name] = decodeURIComponent(value);
      } catch {
        req.cookies[name] = value;
      }
    }
  });

  next();
});

function validSession(req) {
  const value = req.cookies?.[COOKIE_NAME];

  if (!value || typeof value !== "string") return false;

  const parts = value.split(".");
  if (parts.length !== 2) return false;

  const [payload, signature] = parts;

  const expected = crypto.createHmac("sha256", SESSION_SECRET)
    .update(payload)
    .digest("base64url");

  if (!safeEqual(signature, expected)) return false;

  try {
    const data = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8")
    );

    return data.username === ADMIN_USERNAME &&
      Number.isFinite(data.exp) &&
      data.exp > Date.now();
  } catch {
    return false;
  }
}

function sameOriginOnly(req, res, next) {
  const origin = req.get("origin");

  if (origin) {
    try {
      if (new URL(origin).host !== req.get("host")) {
        return res.status(403).json({
          success: false,
          message: "Yêu cầu không hợp lệ"
        });
      }
    } catch {
      return res.status(403).json({
        success: false,
        message: "Yêu cầu không hợp lệ"
      });
    }
  }

  next();
}

function adminOnly(req, res, next) {
  if (validSession(req)) return next();

  const auth = req.headers.authorization || "";

  if (ADMIN_TOKEN && safeEqual(auth, "Bearer " + ADMIN_TOKEN)) {
    return next();
  }

  return res.status(401).json({
    success: false,
    message: "Phiên Admin đã hết hạn hoặc không hợp lệ"
  });
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 8,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    message: "Bạn đăng nhập quá nhiều lần. Vui lòng thử lại sau."
  }
});

/* =========================
   BASIC ROUTES
========================= */

app.get("/health", (req, res) => {
  res.json({ success: true, service: "AIMLOCK API" });
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

/* =========================
   ADMIN LOGIN / LOGOUT
========================= */

app.post(
  "/api/admin/login",
  sameOriginOnly,
  loginLimiter,
  (req, res) => {
    const username =
      typeof req.body?.username === "string"
        ? req.body.username
        : "";

    const password =
      typeof req.body?.password === "string"
        ? req.body.password
        : "";

    if (
      !safeEqual(username, ADMIN_USERNAME) ||
      !safeEqual(password, ADMIN_PASSWORD)
    ) {
      return res.status(401).json({
        success: false,
        message: "Sai tài khoản hoặc mật khẩu Admin"
      });
    }

    createSessionCookie(res, username);

    return res.json({
      success: true,
      message: "Đăng nhập thành công",
      expiresInDays: SESSION_DAYS
    });
  }
);

app.get("/api/admin/session", (req, res) => {
  res.json({ success: validSession(req) });
});

app.post("/api/admin/logout", sameOriginOnly, (req, res) => {
  clearSessionCookie(res);
  res.json({ success: true, message: "Đã đăng xuất" });
});

/* =========================
   APP KEY VERIFICATION
========================= */

app.post(
  "/api/keys/verify",
  rateLimit({
    windowMs: 60 * 1000,
    limit: 20,
    standardHeaders: true,
    legacyHeaders: false
  }),
  async (req, res) => {
    const client = await pool.connect();

    try {
      const key = req.body?.key;
      const deviceId = req.body?.deviceId || req.body?.device_id;

      const deviceLabel =
        typeof req.body?.deviceLabel === "string"
          ? req.body.deviceLabel
              .replace(/[^a-zA-Z0-9 _.-]/g, "")
              .slice(0, 40)
          : "Thiet bi";

      if (
        typeof key !== "string" ||
        key.length < 8 ||
        key.length > 100
      ) {
        return res.status(400).json({
          success: false,
          message: "KEY không hợp lệ"
        });
      }

      await client.query("BEGIN");

      const result = await client.query(
        `SELECT id, status, expires_at, created_at, activated_at,
                duration_type, max_devices, device_limit_enforced
         FROM license_keys
         WHERE key_hash = $1
         FOR UPDATE`,
        [hashKey(key)]
      );

      if (!result.rowCount) {
        await client.query("ROLLBACK");
        return res.status(404).json({
          success: false,
          message: "KEY không tồn tại"
        });
      }

      const license = result.rows[0];

      if (license.status !== "active") {
        await client.query("ROLLBACK");
        return res.status(403).json({
          success: false,
          message: "KEY đã bị khóa"
        });
      }

      if (
        license.expires_at &&
        new Date(license.expires_at) <= new Date()
      ) {
        await client.query("ROLLBACK");
        return res.status(403).json({
          success: false,
          message: "KEY đã hết hạn"
        });
      }

      if (license.device_limit_enforced) {
        if (
          typeof deviceId !== "string" ||
          deviceId.trim().length < 8 ||
          deviceId.length > 200
        ) {
          await client.query("ROLLBACK");
          return res.status(400).json({
            success: false,
            code: "DEVICE_ID_REQUIRED",
            message: "Ứng dụng cần gửi mã thiết bị"
          });
        }

        const deviceHash = hashDeviceId(deviceId);

        const existing = await client.query(
          `SELECT id, status
           FROM license_devices
           WHERE license_id = $1 AND device_hash = $2
           FOR UPDATE`,
          [license.id, deviceHash]
        );

        if (existing.rowCount) {
          if (existing.rows[0].status === "blocked") {
            await client.query("ROLLBACK");
            return res.status(403).json({
              success: false,
              code: "DEVICE_BLOCKED",
              message: "Thiết bị này đã bị Admin khóa"
            });
          }

          await client.query(
            `UPDATE license_devices
             SET last_seen_at = NOW()
             WHERE id = $1`,
            [existing.rows[0].id]
          );
        } else {
          const countResult = await client.query(
            `SELECT COUNT(*)::int AS total
             FROM license_devices
             WHERE license_id = $1`,
            [license.id]
          );

          const used = countResult.rows[0].total;

          if (used >= license.max_devices) {
            await client.query("ROLLBACK");
            return res.status(403).json({
              success: false,
              code: "DEVICE_LIMIT_REACHED",
              message: "KEY đã đạt giới hạn thiết bị"
            });
          }

          await client.query(
            `INSERT INTO license_devices
              (license_id, device_hash, device_hint, status)
             VALUES ($1, $2, $3, 'active')`,
            [
              license.id,
              deviceHash,
              deviceLabel + " · ..." + deviceId.slice(-4)
            ]
          );
        }
      }

      const activation = await client.query(
        `UPDATE license_keys
         SET activated_at = COALESCE(activated_at, NOW())
         WHERE id = $1
         RETURNING activated_at`,
        [license.id]
      );

      const countResult = await client.query(
        `SELECT COUNT(*)::int AS total
         FROM license_devices
         WHERE license_id = $1`,
        [license.id]
      );

      await client.query("COMMIT");

      return res.json({
        success: true,
        message: "Xác thực KEY thành công",
        status: license.status,
        durationType: license.duration_type,
        activatedAt: activation.rows[0].activated_at,
        createdAt: license.created_at,
        expiresAt: license.expires_at,
        devicesUsed: countResult.rows[0].total,
        deviceCount: countResult.rows[0].total,
        maxDevices: license.max_devices,
        deviceLimit: license.max_devices,
        deviceLimitEnforced: license.device_limit_enforced
      });

    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      console.error("Key verification error:", error);

      return res.status(500).json({
        success: false,
        message: "Lỗi máy chủ"
      });
    } finally {
      client.release();
    }
  }
);

/* =========================
   ADMIN: LIST KEYS + DEVICES
========================= */

app.get("/api/admin/keys", adminOnly, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
         k.id,
         k.key_hint,
         k.status,
         k.expires_at,
         k.created_at,
         k.activated_at,
         k.note,
         k.duration_type,
         k.duration_value,
         k.max_devices,
         (k.encrypted_key IS NOT NULL) AS can_copy,

         COUNT(d.id)::int AS devices_used,

         COALESCE(
           json_agg(
             json_build_object(
               'id', d.id,
               'deviceHint', d.device_hint,
               'status', d.status,
               'firstSeenAt', d.first_seen_at,
               'lastSeenAt', d.last_seen_at
             )
             ORDER BY d.first_seen_at
           ) FILTER (WHERE d.id IS NOT NULL),
           '[]'::json
         ) AS devices

       FROM license_keys k
       LEFT JOIN license_devices d ON d.license_id = k.id
       GROUP BY k.id
       ORDER BY k.created_at DESC`
    );

    res.json({
      success: true,
      keys: result.rows
    });
  } catch (error) {
    console.error("List keys error:", error);

    res.status(500).json({
      success: false,
      message: "Không tải được danh sách Key"
    });
  }
});

/* =========================
   ADMIN: CREATE KEY
========================= */

app.post(
  "/api/admin/keys",
  sameOriginOnly,
  adminOnly,
  async (req, res) => {
    try {
      const type = String(req.body?.durationType || "");
      const amount = Number(req.body?.durationValue);
      const maxDevices = Number(req.body?.maxDevices);
      const note = String(req.body?.note || "").slice(0, 200);

      const allowed = [
        "hours", "days", "weeks",
        "months", "years", "permanent"
      ];

      if (!allowed.includes(type)) {
        return res.status(400).json({
          success: false,
          message: "Loại thời hạn không hợp lệ"
        });
      }

      if (
        type !== "permanent" &&
        (!Number.isSafeInteger(amount) || amount < 1 || amount > 100000)
      ) {
        return res.status(400).json({
          success: false,
          message: "Thời hạn không hợp lệ"
        });
      }

      if (
        !Number.isSafeInteger(maxDevices) ||
        maxDevices < 1 ||
        maxDevices > 100000
      ) {
        return res.status(400).json({
          success: false,
          message: "Số thiết bị không hợp lệ"
        });
      }

      let key;
      let inserted;

      for (let attempt = 0; attempt < 5; attempt++) {
        key = makeKey();

        const now = new Date();
        const expiresAt = type === "permanent"
          ? null
          : addDuration(now, type, amount);

        try {
          inserted = await pool.query(
            `INSERT INTO license_keys
              (key_hash, key_hint, encrypted_key, status,
               expires_at, note, duration_type, duration_value,
               max_devices, device_limit_enforced)
             VALUES ($1, $2, $3, 'active', $4, $5, $6, $7, $8, TRUE)
             RETURNING id, created_at, expires_at`,
            [
              hashKey(key),
              "****-" + key.slice(-4),
              encryptKey(key),
              expiresAt,
              note,
              type,
              type === "permanent" ? null : amount,
              maxDevices
            ]
          );

          break;
        } catch (error) {
          if (error.code !== "23505" || attempt === 4) {
            throw error;
          }
        }
      }

      return res.json({
        success: true,
        key,
        id: inserted.rows[0].id,
        createdAt: inserted.rows[0].created_at,
        expiresAt: inserted.rows[0].expires_at,
        durationType: type,
        durationValue: type === "permanent" ? null : amount,
        maxDevices
      });

    } catch (error) {
      console.error("Create key error:", error);

      res.status(500).json({
        success: false,
        message: "Không tạo được Key"
      });
    }
  }
);

/* =========================
   ADMIN: COPY KEY
========================= */

app.post(
  "/api/admin/keys/:id/copy",
  sameOriginOnly,
  adminOnly,
  async (req, res) => {
    try {
      const id = Number(req.params.id);

      if (!Number.isSafeInteger(id) || id < 1) {
        return res.status(400).json({
          success: false,
          message: "ID không hợp lệ"
        });
      }

      const result = await pool.query(
        "SELECT encrypted_key FROM license_keys WHERE id = $1",
        [id]
      );

      if (!result.rowCount) {
        return res.status(404).json({
          success: false,
          message: "Không tìm thấy Key"
        });
      }

      if (!result.rows[0].encrypted_key) {
        return res.status(409).json({
          success: false,
          message: "Key cũ chỉ lưu mã băm nên không thể khôi phục để sao chép."
        });
      }

      return res.json({
        success: true,
        key: decryptKey(result.rows[0].encrypted_key)
      });

    } catch (error) {
      console.error("Copy key error:", error);

      res.status(500).json({
        success: false,
        message: "Không thể giải mã Key. Kiểm tra KEY_ENCRYPTION_SECRET."
      });
    }
  }
);

/* =========================
   ADMIN: LOCK / UNLOCK KEY
========================= */

async function setKeyStatus(req, res, status) {
  try {
    const id = Number(req.params.id);

    if (!Number.isSafeInteger(id) || id < 1) {
      return res.status(400).json({
        success: false,
        message: "ID không hợp lệ"
      });
    }

    const result = await pool.query(
      "UPDATE license_keys SET status = $1 WHERE id = $2",
      [status, id]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        success: false,
        message: "Không tìm thấy Key"
      });
    }

    res.json({
      success: true,
      message: status === "active" ? "Đã mở khóa Key" : "Đã khóa Key"
    });

  } catch (error) {
    console.error("Update key status error:", error);

    res.status(500).json({
      success: false,
      message: "Không cập nhật được Key"
    });
  }
}

app.post(
  "/api/admin/keys/:id/lock",
  sameOriginOnly,
  adminOnly,
  (req, res) => setKeyStatus(req, res, "locked")
);

app.post(
  "/api/admin/keys/:id/unlock",
  sameOriginOnly,
  adminOnly,
  (req, res) => setKeyStatus(req, res, "active")
);

app.post(
  "/api/admin/keys/:id/revoke",
  sameOriginOnly,
  adminOnly,
  (req, res) => setKeyStatus(req, res, "revoked")
);

/* =========================
   ADMIN: DEVICE MANAGEMENT
========================= */

async function setDeviceStatus(req, res, status) {
  try {
    const keyId = Number(req.params.id);
    const deviceId = Number(req.params.deviceId);

    if (
      !Number.isSafeInteger(keyId) || keyId < 1 ||
      !Number.isSafeInteger(deviceId) || deviceId < 1
    ) {
      return res.status(400).json({
        success: false,
        message: "ID thiết bị không hợp lệ"
      });
    }

    const result = await pool.query(
      `UPDATE license_devices
       SET status = $1
       WHERE id = $2 AND license_id = $3`,
      [status, deviceId, keyId]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        success: false,
        message: "Không tìm thấy thiết bị thuộc Key này"
      });
    }

    res.json({
      success: true,
      message: status === "active"
        ? "Đã mở khóa thiết bị"
        : "Đã khóa thiết bị"
    });

  } catch (error) {
    console.error("Device status error:", error);

    res.status(500).json({
      success: false,
      message: "Không cập nhật được thiết bị"
    });
  }
}

app.post(
  "/api/admin/keys/:id/devices/:deviceId/block",
  sameOriginOnly,
  adminOnly,
  (req, res) => setDeviceStatus(req, res, "blocked")
);

app.post(
  "/api/admin/keys/:id/devices/:deviceId/unblock",
  sameOriginOnly,
  adminOnly,
  (req, res) => setDeviceStatus(req, res, "active")
);

app.delete(
  "/api/admin/keys/:id/devices/:deviceId",
  sameOriginOnly,
  adminOnly,
  async (req, res) => {
    try {
      const keyId = Number(req.params.id);
      const deviceId = Number(req.params.deviceId);

      if (
        !Number.isSafeInteger(keyId) || keyId < 1 ||
        !Number.isSafeInteger(deviceId) || deviceId < 1
      ) {
        return res.status(400).json({
          success: false,
          message: "ID thiết bị không hợp lệ"
        });
      }

      const result = await pool.query(
        `DELETE FROM license_devices
         WHERE id = $1 AND license_id = $2`,
        [deviceId, keyId]
      );

      if (!result.rowCount) {
        return res.status(404).json({
          success: false,
          message: "Không tìm thấy thiết bị thuộc Key này"
        });
      }

      const count = await pool.query(
        `SELECT COUNT(*)::int AS total
         FROM license_devices
         WHERE license_id = $1`,
        [keyId]
      );

      res.json({
        success: true,
        message: "Đã xóa thiết bị",
        devicesUsed: count.rows[0].total
      });

    } catch (error) {
      console.error("Delete device error:", error);

      res.status(500).json({
        success: false,
        message: "Không xóa được thiết bị"
      });
    }
  }
);

/* =========================
   ADMIN: DELETE KEY
========================= */

app.delete(
  "/api/admin/keys/:id",
  sameOriginOnly,
  adminOnly,
  async (req, res) => {
    try {
      const id = Number(req.params.id);

      if (!Number.isSafeInteger(id) || id < 1) {
        return res.status(400).json({
          success: false,
          message: "ID không hợp lệ"
        });
      }

      const result = await pool.query(
        "DELETE FROM license_keys WHERE id = $1",
        [id]
      );

      if (!result.rowCount) {
        return res.status(404).json({
          success: false,
          message: "Không tìm thấy Key"
        });
      }

      res.json({
        success: true,
        message: "Đã xóa Key"
      });

    } catch (error) {
      console.error("Delete key error:", error);

      res.status(500).json({
        success: false,
        message: "Không xóa được Key"
      });
    }
  }
);

/* =========================
   DATABASE
========================= */

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS license_keys (
      id BIGSERIAL PRIMARY KEY,
      key_hash TEXT UNIQUE NOT NULL,
      key_hint TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      note TEXT,
      duration_type TEXT NOT NULL DEFAULT 'days',
      duration_value INTEGER,
      activated_at TIMESTAMPTZ,
      encrypted_key TEXT,
      max_devices INTEGER NOT NULL DEFAULT 1,
      device_limit_enforced BOOLEAN NOT NULL DEFAULT TRUE
    )
  `);

  await pool.query(`
    ALTER TABLE license_keys
      ALTER COLUMN expires_at DROP NOT NULL,
      ADD COLUMN IF NOT EXISTS duration_type TEXT NOT NULL DEFAULT 'days',
      ADD COLUMN IF NOT EXISTS duration_value INTEGER,
      ADD COLUMN IF NOT EXISTS activated_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS encrypted_key TEXT,
      ADD COLUMN IF NOT EXISTS max_devices INTEGER NOT NULL DEFAULT 1,
      ADD COLUMN IF NOT EXISTS device_limit_enforced BOOLEAN NOT NULL DEFAULT TRUE
  `);

  await pool.query(`
    UPDATE license_keys
    SET device_limit_enforced = TRUE
    WHERE device_limit_enforced = FALSE
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS license_devices (
      id BIGSERIAL PRIMARY KEY,
      license_id BIGINT NOT NULL
        REFERENCES license_keys(id) ON DELETE CASCADE,
      device_hash TEXT NOT NULL,
      device_hint TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (license_id, device_hash)
    )
  `);

  /* Migration for existing device tables */
  await pool.query(`
    ALTER TABLE license_devices
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_license_devices_license_id
    ON license_devices(license_id)
  `);
}

/* =========================
   START
========================= */

initDatabase()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`AIMLOCK API running on port ${PORT}`);
    });
  })
  .catch(error => {
    console.error("Database initialization failed:", error);
    process.exit(1);
  });
