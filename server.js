require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const path = require("path");
const User = require("./user");

const app = express();
const PORT = Number(process.env.PORT || 5000);
const JWT_SECRET = process.env.JWT_SECRET;
const NODE_ENV = String(process.env.NODE_ENV || "development").toLowerCase();
const JWT_ISSUER = "kf8-api";
const JWT_AUDIENCE = "kf8-web";

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("JWT_SECRET is missing or too short. Use at least 32 random characters.");
  process.exit(1);
}

app.disable("x-powered-by");
app.set("trust proxy", 1);
const allowedOrigins = String(process.env.ALLOWED_ORIGINS || "https://rahul-play.onrender.com")
  .split(",").map(x => x.trim().replace(/\/$/, "")).filter(Boolean);

app.use((req, res, next) => {
  // Security headers without extra npm dependencies.
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  res.setHeader("Cross-Origin-Resource-Policy", "same-site");
  res.setHeader("X-DNS-Prefetch-Control", "off");
  if (req.secure || String(req.headers["x-forwarded-proto"] || "").toLowerCase() === "https") {
    res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  }
  if (/^\/api\/(auth|admin)/.test(req.path)) {
    res.setHeader("Cache-Control", "no-store, max-age=0");
    res.setHeader("Pragma", "no-cache");
  }
  next();
});

app.use(cors({
  origin: (origin, callback) => {
    // Non-browser/server-to-server requests have no Origin header.
    if (!origin) return callback(null, true);
    const normalized = String(origin).replace(/\/$/, "");
    if (allowedOrigins.includes(normalized)) return callback(null, true);
    return callback(new Error("CORS origin denied"));
  },
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "Accept", "Idempotency-Key"],
  maxAge: 86400,
  credentials: false
}));
app.use(express.json({ limit: "64kb", strict: true }));

function hasDangerousKeys(value) {
  if (!value || typeof value !== "object") return false;
  for (const [key, child] of Object.entries(value)) {
    if (key === "__proto__" || key === "prototype" || key === "constructor" || key.startsWith("$") || key.includes(".")) return true;
    if (hasDangerousKeys(child)) return true;
  }
  return false;
}
app.use((req, res, next) => {
  if (hasDangerousKeys(req.body)) return res.status(400).json({ success:false, message:"Invalid request payload." });
  next();
});

// Small in-memory rate limiter. For multiple Render instances, move this to Redis.
const rateBuckets = new Map();
function rateLimit({ windowMs, max, keyPrefix="global" }) {
  return (req, res, next) => {
    const now = Date.now();
    const ip = String(req.ip || req.socket?.remoteAddress || "unknown");
    const key = `${keyPrefix}:${ip}`;
    let row = rateBuckets.get(key);
    if (!row || row.resetAt <= now) row = { count:0, resetAt:now + windowMs };
    row.count += 1; rateBuckets.set(key, row);
    res.setHeader("X-RateLimit-Limit", String(max));
    res.setHeader("X-RateLimit-Remaining", String(Math.max(0, max-row.count)));
    if (row.count > max) {
      const retry = Math.max(1, Math.ceil((row.resetAt-now)/1000));
      res.setHeader("Retry-After", String(retry));
      return res.status(429).json({ success:false, message:"Too many requests. Please try again later." });
    }
    next();
  };
}
const generalLimiter = rateLimit({ windowMs:60_000, max:240, keyPrefix:"general" });
const loginLimiter = rateLimit({ windowMs:15*60_000, max:20, keyPrefix:"login" });
const adminUnlockLimiter = rateLimit({ windowMs:15*60_000, max:8, keyPrefix:"admin-unlock" });
const forgotLimiter = rateLimit({ windowMs:15*60_000, max:5, keyPrefix:"forgot" });
const resetLimiter = rateLimit({ windowMs:15*60_000, max:10, keyPrefix:"reset" });
app.use("/api", generalLimiter);
setInterval(() => {
  const now=Date.now();
  for (const [k,v] of rateBuckets) if (v.resetAt <= now) rateBuckets.delete(k);
  if (rateBuckets.size > 20000) rateBuckets.clear();
}, 5*60_000).unref?.();

/* =========================
   RESULT + BET MODELS
========================= */

const resultSchema = new mongoose.Schema(
  {
    key: { type: String, unique: true, default: "main" },
    dayKey: { type: String, default: "" },
    sourceUpdatedAt: { type: Date, default: null },
    sourceName: { type: String, default: "" },
    results: {
      type: [
        {
          baji: Number,
          patti: String,
          single: String,
          declared: Boolean,
          resultAt: String
        }
      ],
      default: []
    }
  },
  { timestamps: true }
);

const Result = mongoose.models.KF8Result || mongoose.model("KF8Result", resultSchema);

const betSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
    username: { type: String, required: true },
    baji: { type: Number, required: true, min: 1, max: 8, index: true },
    gameDay: { type: String, default: "", index: true },
    betType: { type: String, enum: ["single", "patti", "jodi"], required: true },
    rawTarget: { type: String, required: true },
    stake: { type: Number, required: true, min: 0.01 },
    multiplier: { type: Number, required: true },
    payout: { type: Number, required: true },
    status: { type: String, enum: ["Pending", "WON", "LOST"], default: "Pending", index: true },
    result: { type: String, default: null },
    createdAt: { type: Date, default: Date.now },
    settledAt: { type: Date, default: null }
  },
  { timestamps: true }
);

const Bet = mongoose.models.KF8Bet || mongoose.model("KF8Bet", betSchema);


/* =========================
   PRACTICE SINGLE + PATTI DATABASE
   Virtual Practice PTS only.
   This system never writes to winningBalance/withdrawableBalance.
========================= */

const practiceWalletSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      unique: true,
      index: true
    },
    username: { type: String, required: true, index: true },
    balance: { type: Number, required: true, default: 0, min: 0 },
    initialBalance: { type: Number, required: true, default: 0 },
    creditedEvents: { type: [String], default: [] },
    initializedAt: { type: Date, default: Date.now }
  },
  { timestamps: true }
);

const PracticeWallet =
  mongoose.models.KF8PracticeWallet ||
  mongoose.model("KF8PracticeWallet", practiceWalletSchema);

const practiceSingleBetSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true
    },
    username: { type: String, required: true, index: true },
    baji: { type: Number, required: true, min: 1, max: 8, index: true },
    gameDay: { type: String, required: true, index: true },
    digit: { type: String, required: true },
    stake: { type: Number, required: true, min: 0.01 },
    multiplier: { type: Number, required: true, default: 9 },
    payout: { type: Number, required: true },
    status: {
      type: String,
      enum: ["Pending", "WON", "LOST"],
      default: "Pending",
      index: true
    },
    result: { type: String, default: null },
    settledAt: { type: Date, default: null },
    walletCredited: { type: Boolean, default: false },
    clientRequestId: { type: String, required: true }
  },
  { timestamps: true }
);

practiceSingleBetSchema.index(
  { userId: 1, clientRequestId: 1 },
  {
    unique: true,
    partialFilterExpression: { clientRequestId: { $type: "string" } }
  }
);
practiceSingleBetSchema.index(
  { userId: 1, gameDay: 1, baji: 1, digit: 1, status: 1 }
);

const PracticeSingleBet =
  mongoose.models.KF8PracticeSingleBet ||
  mongoose.model("KF8PracticeSingleBet", practiceSingleBetSchema);

const practicePattiBetSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true
    },
    username: { type: String, required: true, index: true },
    baji: { type: Number, required: true, min: 1, max: 8, index: true },
    gameDay: { type: String, required: true, index: true },
    patti: { type: String, required: true },
    stake: { type: Number, required: true, min: 0.01 },
    multiplier: { type: Number, required: true, default: 90 },
    payout: { type: Number, required: true },
    status: {
      type: String,
      enum: ["Pending", "WON", "LOST"],
      default: "Pending",
      index: true
    },
    result: { type: String, default: null },
    settledAt: { type: Date, default: null },
    walletCredited: { type: Boolean, default: false },
    pairSingleBetId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "KF8PracticeSingleBet",
      required: true,
      index: true
    },
    clientRequestId: { type: String, required: true }
  },
  { timestamps: true }
);

practicePattiBetSchema.index(
  { userId: 1, clientRequestId: 1 },
  {
    unique: true,
    partialFilterExpression: { clientRequestId: { $type: "string" } }
  }
);
practicePattiBetSchema.index(
  { userId: 1, gameDay: 1, baji: 1, patti: 1, status: 1 }
);

const PracticePattiBet =
  mongoose.models.KF8PracticePattiBet ||
  mongoose.model("KF8PracticePattiBet", practicePattiBetSchema);

function cleanPracticeRequestId(value) {
  const s = String(value || "").trim();
  if (!s) return "";
  return s.replace(/[^a-zA-Z0-9_.:-]/g, "").slice(0, 100);
}

async function ensurePracticeWallet(user) {
  let wallet = await PracticeWallet.findOne({ userId: user._id });
  if (wallet) return wallet;

  const seed = Math.max(0, Number(user.balance || 0));

  try {
    wallet = await PracticeWallet.create({
      userId: user._id,
      username: user.username,
      balance: seed,
      initialBalance: seed,
      creditedEvents: [],
      initializedAt: new Date()
    });
  } catch (err) {
    if (err?.code !== 11000) throw err;
    wallet = await PracticeWallet.findOne({ userId: user._id });
  }

  if (!wallet) throw new Error("Practice Wallet could not be initialized.");
  return wallet;
}

function practiceHistoryRows(singleBets, pattiBets) {
  const out = [];

  for (const bet of Array.from(singleBets || [])) {
    const id = String(bet._id);
    const stake = Number(bet.stake || 0);
    const payout = Number(bet.payout || 0);

    out.push({
      id: `practice-db-single-entry-${id}`,
      type: "Practice Single Entry",
      details: `Snake Play Baji ${bet.baji} • Single ${bet.digit}`,
      baji: Number(bet.baji),
      target: `Single Digit (${bet.digit})`,
      rawTarget: String(bet.digit),
      betType: "practice-single",
      clientRequestId: String(bet.clientRequestId || ""),
      stake,
      amount: -stake,
      status: String(bet.status || "Pending"),
      result: bet.result || null,
      date: bet.createdAt
    });

    if (String(bet.status) === "WON") {
      out.push({
        id: `practice-db-single-payout-${id}`,
        type: "Practice Single Payout",
        details: `Snake Play Baji ${bet.baji} • Single ${bet.digit} • 9x payout`,
        baji: Number(bet.baji),
        target: `Single Digit (${bet.digit})`,
        rawTarget: String(bet.digit),
        betType: "practice-single-payout",
        clientRequestId: String(bet.clientRequestId || ""),
        stake,
        payout,
        amount: payout,
        status: bet.walletCredited ? "Credited" : "Processing",
        result: bet.result || null,
        date: bet.settledAt || bet.updatedAt || bet.createdAt
      });
    }
  }

  for (const bet of Array.from(pattiBets || [])) {
    const id = String(bet._id);
    const stake = Number(bet.stake || 0);
    const payout = Number(bet.payout || 0);

    out.push({
      id: `practice-db-patti-entry-${id}`,
      type: "Practice Patti Entry",
      details: `Snake Play Baji ${bet.baji} • Patti ${bet.patti}`,
      baji: Number(bet.baji),
      target: `Patti (${bet.patti})`,
      rawTarget: String(bet.patti),
      betType: "practice-patti",
      clientRequestId: String(bet.clientRequestId || ""),
      stake,
      amount: -stake,
      status: String(bet.status || "Pending"),
      result: bet.result || null,
      pairSingleBetId: String(bet.pairSingleBetId || ""),
      date: bet.createdAt
    });

    if (String(bet.status) === "WON") {
      out.push({
        id: `practice-db-patti-payout-${id}`,
        type: "Practice Patti Payout",
        details: `Snake Play Baji ${bet.baji} • Patti ${bet.patti} • 90x payout`,
        baji: Number(bet.baji),
        target: `Patti (${bet.patti})`,
        rawTarget: String(bet.patti),
        betType: "practice-patti-payout",
        clientRequestId: String(bet.clientRequestId || ""),
        stake,
        payout,
        amount: payout,
        status: bet.walletCredited ? "Credited" : "Processing",
        result: bet.result || null,
        pairSingleBetId: String(bet.pairSingleBetId || ""),
        date: bet.settledAt || bet.updatedAt || bet.createdAt
      });
    }
  }

  return out.sort(
    (a, b) => new Date(b?.date || 0).getTime() - new Date(a?.date || 0).getTime()
  );
}

async function practiceAccountPayload(user) {
  const wallet = await ensurePracticeWallet(user);

  const [singleBets, pattiBets] = await Promise.all([
    PracticeSingleBet.find({ userId: user._id })
      .sort({ createdAt: -1 })
      .limit(200)
      .lean(),
    PracticePattiBet.find({ userId: user._id })
      .sort({ createdAt: -1 })
      .limit(200)
      .lean()
  ]);

  return {
    practiceBalance: Number(wallet.balance || 0),
    practiceHistory: practiceHistoryRows(singleBets, pattiBets),
    practiceVersion: 3
  };
}

async function practicePayloadBestEffort(user, walletHint = null) {
  try {
    return await practiceAccountPayload(user);
  } catch (err) {
    console.error("PRACTICE PAYLOAD ERROR:", err?.message || err);
    return {
      practiceBalance: Number(walletHint?.balance || 0),
      practiceVersion: 3
    };
  }
}

async function notifyPracticeUser(userId) {
  try {
    const user = await User.findById(userId);
    if (!user) return;

    const practice = await practiceAccountPayload(user);
    sendEventToUser(
      user._id,
      "practice-account",
      { success: true, ...practice }
    );
  } catch (err) {
    console.error("PRACTICE NOTIFY ERROR:", err?.message || err);
  }
}

async function creditPracticeWalletOnce(userId, eventKey, amount) {
  const value = Number(Number(amount || 0).toFixed(2));
  if (!(value > 0)) return PracticeWallet.findOne({ userId });

  let wallet = await PracticeWallet.findOneAndUpdate(
    {
      userId,
      creditedEvents: { $ne: String(eventKey) }
    },
    {
      $inc: { balance: value },
      $addToSet: { creditedEvents: String(eventKey) }
    },
    { new: true }
  );

  if (wallet) return wallet;
  return PracticeWallet.findOne({ userId });
}

async function settlePracticeSingleRow(row, winningSingle) {
  let doc = row;

  if (String(row.status) === "Pending") {
    const won = String(row.digit) === String(winningSingle);

    doc = await PracticeSingleBet.findOneAndUpdate(
      { _id: row._id, status: "Pending" },
      {
        $set: {
          status: won ? "WON" : "LOST",
          result: String(winningSingle),
          settledAt: new Date(),
          walletCredited: false
        }
      },
      { new: true }
    );

    if (!doc) return { touchedUserId: null, newlyWon: false };
  }

  if (String(doc.status) === "WON" && doc.walletCredited !== true) {
    const eventKey = `practice-single-win:${String(doc._id)}`;

    await creditPracticeWalletOnce(
      doc.userId,
      eventKey,
      Number(doc.payout || 0)
    );

    await PracticeSingleBet.updateOne(
      { _id: doc._id },
      { $set: { walletCredited: true } }
    );
  }

  return {
    touchedUserId: String(doc.userId),
    newlyWon: String(row.status) === "Pending" && String(doc.status) === "WON"
  };
}

async function settlePracticePattiRow(row, winningPatti) {
  let doc = row;

  if (String(row.status) === "Pending") {
    const won = String(row.patti) === String(winningPatti);

    doc = await PracticePattiBet.findOneAndUpdate(
      { _id: row._id, status: "Pending" },
      {
        $set: {
          status: won ? "WON" : "LOST",
          result: String(winningPatti),
          settledAt: new Date(),
          walletCredited: false
        }
      },
      { new: true }
    );

    if (!doc) return { touchedUserId: null, newlyWon: false };
  }

  if (String(doc.status) === "WON" && doc.walletCredited !== true) {
    const eventKey = `practice-patti-win:${String(doc._id)}`;

    await creditPracticeWalletOnce(
      doc.userId,
      eventKey,
      Number(doc.payout || 0)
    );

    await PracticePattiBet.updateOne(
      { _id: doc._id },
      { $set: { walletCredited: true } }
    );
  }

  return {
    touchedUserId: String(doc.userId),
    newlyWon: String(row.status) === "Pending" && String(doc.status) === "WON"
  };
}

async function settlePracticePattiBaji(baji, patti) {
  const dayKey = currentGameDayKey();
  const winningPatti = String(patti);
  const winningSingle = String(pattiSingle(winningPatti) ?? "");

  const [singleRows, pattiRows] = await Promise.all([
    PracticeSingleBet.find({
      baji: Number(baji),
      gameDay: dayKey,
      $or: [
        { status: "Pending" },
        { status: "WON", walletCredited: { $ne: true } }
      ]
    }),
    PracticePattiBet.find({
      baji: Number(baji),
      gameDay: dayKey,
      $or: [
        { status: "Pending" },
        { status: "WON", walletCredited: { $ne: true } }
      ]
    })
  ]);

  let winners = 0;
  const touchedUsers = new Set();

  for (const row of singleRows) {
    const r = await settlePracticeSingleRow(row, winningSingle);
    if (r.touchedUserId) touchedUsers.add(r.touchedUserId);
    if (r.newlyWon) winners += 1;
  }

  for (const row of pattiRows) {
    const r = await settlePracticePattiRow(row, winningPatti);
    if (r.touchedUserId) touchedUsers.add(r.touchedUserId);
    if (r.newlyWon) winners += 1;
  }

  for (const userId of touchedUsers) {
    await notifyPracticeUser(userId);
  }

  return winners;
}

/* =========================
   DEMO LEDGER + AUDIT
   Virtual/demo points only.
========================= */
const ledgerSchema = new mongoose.Schema({
  eventKey: { type: String, required: true, unique: true, index: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
  username: { type: String, required: true, index: true },
  type: { type: String, required: true },
  amount: { type: Number, required: true },
  balanceBefore: { type: Number, required: true },
  balanceAfter: { type: Number, required: true },
  referenceId: { type: String, required: true, index: true },
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
  createdAt: { type: Date, default: Date.now, immutable: true }
}, { versionKey: false });
const Ledger = mongoose.models.KF8DemoLedger || mongoose.model("KF8DemoLedger", ledgerSchema);

const auditSchema = new mongoose.Schema({
  actorUserId: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true },
  actorUsername: { type: String, index: true },
  action: { type: String, required: true, index: true },
  targetUserId: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true },
  referenceId: { type: String, index: true },
  ip: String,
  userAgent: String,
  details: { type: mongoose.Schema.Types.Mixed, default: {} },
  createdAt: { type: Date, default: Date.now, immutable: true }
}, { versionKey: false });
const AuditLog = mongoose.models.KF8AuditLog || mongoose.model("KF8AuditLog", auditSchema);

async function recordLedger(user, type, delta, referenceId, metadata = {}) {
  const amount = Number(delta || 0);
  const after = Number(user.balance || 0);
  const before = Number((after - amount).toFixed(2));
  const eventKey = `${type}:${String(referenceId)}`;
  try {
    return await Ledger.create({
      eventKey, userId: user._id, username: user.username, type,
      amount: Number(amount.toFixed(2)), balanceBefore: before,
      balanceAfter: after, referenceId: String(referenceId), metadata
    });
  } catch (err) {
    if (err?.code === 11000) return Ledger.findOne({ eventKey }).lean();
    throw err;
  }
}

async function writeAudit(req, action, targetUser, referenceId, details = {}) {
  try {
    await AuditLog.create({
      actorUserId: req.auth?.id,
      actorUsername: req.auth?.username,
      action,
      targetUserId: targetUser?._id,
      referenceId: referenceId ? String(referenceId) : undefined,
      ip: String(req.headers["x-forwarded-for"] || req.ip || "").split(",")[0].trim(),
      userAgent: String(req.headers["user-agent"] || "").slice(0, 300),
      details
    });
  } catch (err) {
    console.error("AUDIT LOG ERROR:", err);
  }
}

/* =========================
   REAL-TIME CONNECTIONS
========================= */

const clients = new Map();

function sendEventToUser(userId, event, data) {
  const set = clients.get(String(userId));
  if (!set) return;
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of set) {
    try { res.write(payload); } catch (_) {}
  }
}

function broadcast(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const set of clients.values()) {
    for (const res of set) {
      try { res.write(payload); } catch (_) {}
    }
  }
}

/* =========================
   HELPERS
========================= */

function publicUser(user) {
  return {
    id: user._id,
    username: user.username,
    email: user.email,
    role: user.role === "admin" || user.isAdmin ? "admin" : "user",
    isAdmin: Boolean(user.isAdmin || user.role === "admin"),
    pts: Number(user.balance || 0),
    balance: Number(user.balance || 0),
    winningBalance: Number(user.winningBalance || 0),
    withdrawableBalance: Number(user.winningBalance || 0),
    totalPredictions: Number(user.totalPredictions || 0),
    wins: Number(user.wins || 0),
    losses: Number(user.losses || 0),
    totalBet: Number(user.totalBet || 0),
    createdAt: user.createdAt
  };
}

function makeToken(user) {
  return jwt.sign(
    {
      id: String(user._id),
      username: user.username,
      role: user.role === "admin" || user.isAdmin ? "admin" : "user",
      v: Number(user.tokenVersion || 0)
    },
    JWT_SECRET,
    { expiresIn: "12h", algorithm:"HS256", issuer:JWT_ISSUER, audience:JWT_AUDIENCE }
  );
}

async function auth(req, res, next) {
  const header = String(req.headers.authorization || "");
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  if (!token) return res.status(401).json({ success:false, message:"Authentication required." });
  try {
    const decoded = jwt.verify(token, JWT_SECRET, { algorithms:["HS256"], issuer:JWT_ISSUER, audience:JWT_AUDIENCE });
    const liveUser = await User.findById(decoded.id).select("_id username role isAdmin +tokenVersion");
    if (!liveUser || Number(decoded.v || 0) !== Number(liveUser.tokenVersion || 0)) {
      return res.status(401).json({ success:false, message:"Session expired. Please sign in again." });
    }
    req.auth = { ...decoded, role: liveUser.role === "admin" || liveUser.isAdmin ? "admin" : "user" };
    req.authUser = liveUser;
    next();
  } catch (_) {
    return res.status(401).json({ success:false, message:"Invalid or expired token." });
  }
}

async function adminOnly(req, res, next) {
  try {
    const user = await User.findById(req.auth?.id).select("_id username email role isAdmin");
    if (!user || !(user.isAdmin || user.role === "admin")) {
      return res.status(403).json({ success: false, message: "Admin access required." });
    }
    req.adminUser = user;
    next();
  } catch (_) {
    return res.status(403).json({ success: false, message: "Admin access required." });
  }
}

function cleanEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function cleanUsername(value) {
  return String(value || "").trim();
}

function cleanAmount(value) {
  const amount = Number(value);
  return Number.isFinite(amount) && amount > 0 ? Number(amount.toFixed(2)) : null;
}

// Canonical 220 Patti chart used by Kolkata FF-style Patti results.
const KF8_220_PATTI = {"0":["000","118","127","136","145","190","226","235","244","280","299","334","370","389","460","479","488","550","569","578","668","677"],"1":["100","119","128","137","146","155","227","236","245","290","335","344","380","399","470","489","560","579","588","669","678","777"],"2":["110","129","138","147","156","200","228","237","246","255","336","345","390","444","480","499","570","589","660","679","688","778"],"3":["111","120","139","148","157","166","229","238","247","256","300","337","346","355","445","490","580","599","670","689","779","788"],"4":["112","130","149","158","167","220","239","248","257","266","338","347","356","400","446","455","590","680","699","770","789","888"],"5":["113","122","140","159","168","177","230","249","258","267","339","348","357","366","447","456","500","555","690","780","799","889"],"6":["114","123","150","169","178","222","240","259","268","277","330","349","358","367","448","457","466","556","600","790","880","899"],"7":["115","124","133","160","179","188","223","250","269","278","340","359","368","377","449","458","467","557","566","700","890","999"],"8":["116","125","134","170","189","224","233","260","279","288","350","369","378","440","459","468","477","558","567","666","800","990"],"9":["117","126","135","144","180","199","225","234","270","289","333","360","379","388","450","469","478","559","568","577","667","900"]};
const KF8_220_PATTI_SET = new Set(Object.values(KF8_220_PATTI).flat());
function pattiSingle(value) {
  const p = String(value || '').replace(/\D/g, '').padStart(3, '0');
  if (!/^\d{3}$/.test(p)) return null;
  return String((Number(p[0]) + Number(p[1]) + Number(p[2])) % 10);
}
function isValid220Patti(value) {
  return KF8_220_PATTI_SET.has(String(value || '').padStart(3, '0'));
}

const BAJI_RESULT_TIMES = {
  1: "10:05",
  2: "11:35",
  3: "13:05",
  4: "14:35",
  5: "16:05",
  6: "17:35",
  7: "19:05",
  8: "20:35"
};

function resultAtForBaji(baji) {
  const value = BAJI_RESULT_TIMES[Number(baji)] || "23:59";
  return value;
}

function indiaNowParts() {
  const parts = new Intl.DateTimeFormat("en-CA", {timeZone:"Asia/Kolkata",year:"numeric",month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",hourCycle:"h23"}).formatToParts(new Date());
  const o = Object.fromEntries(parts.map(p => [p.type,p.value]));
  return {year:+o.year,month:+o.month,day:+o.day,hour:+o.hour,minute:+o.minute};
}
function currentGameDayKey() {
  const p=indiaNowParts(), d=new Date(Date.UTC(p.year,p.month-1,p.day));
  if (p.hour < 8) d.setUTCDate(d.getUTCDate()-1);
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,"0")}-${String(d.getUTCDate()).padStart(2,"0")}`;
}
function blankResults() {
  return Array.from({length:8},(_,i)=>({baji:i+1,patti:"---",single:"-",declared:false,resultAt:resultAtForBaji(i+1)}));
}

function normalizeResults(results) {
  if (!Array.isArray(results)) return null;
  const rows = results.slice(0, 8).map((r, i) => {
    const patti = String(r.patti || "").replace(/\D/g, "").slice(0, 3);
    const valid = isValid220Patti(patti);
    return {
      baji: Number(r.baji || i + 1),
      patti,
      single: valid ? pattiSingle(patti) : "",
      declared: r.declared !== false,
      resultAt: String(r.resultAt || resultAtForBaji(r.baji || i + 1))
    };
  });

  if (rows.length !== 8) return null;
  if (rows.some(r => r.baji < 1 || r.baji > 8 || !isValid220Patti(r.patti) || r.single === null || r.single === "")) {
    return null;
  }
  return rows;
}

async function getResults() {
  const dayKey=currentGameDayKey();
  const doc=await Result.findOne({key:"main"}).lean();
  if (!doc || doc.dayKey !== dayKey) {
    const defaults=blankResults();
    await Result.findOneAndUpdate({key:"main"},{$set:{dayKey,results:defaults}},{upsert:true,new:true,setDefaultsOnInsert:true});
    return defaults;
  }
  const byBaji=new Map((doc.results||[]).map(r=>[Number(r.baji),r]));
  return blankResults().map(f=>{const r=byBaji.get(f.baji); return !r?f:{baji:f.baji,patti:String(r.patti||"---"),single:String(r.single||"-"),declared:Boolean(r.declared),resultAt:String(r.resultAt||resultAtForBaji(f.baji))};});
}

function historyView(user) {
  const newestFirst = (rows) => Array.from(rows || []).sort((a, b) =>
    new Date(b?.date || 0).getTime() - new Date(a?.date || 0).getTime()
  );
  return {
    balance: Number(user.balance || 0),
    winningBalance: Number(user.winningBalance || 0),
    withdrawableBalance: Number(user.winningBalance || 0),
    // These arrays live on the MongoDB User document and are never deleted
    // after approval/rejection/settlement. Only their status is updated.
    depositHistory: newestFirst(user.depositHistory),
    withdrawalHistory: newestFirst(user.withdrawalHistory),
    gameHistory: newestFirst(user.gameHistory),
    transactionHistory: newestFirst(user.transactionHistory)
  };
}

async function notifyUser(user) {
  sendEventToUser(user._id, "account", { user: publicUser(user), history: historyView(user) });
}

setInterval(() => {
  getResults().then(results => broadcast("results",{results})).catch(err => console.error("RESULT DAY ROLLOVER CHECK:",err.message));
},60000).unref?.();


/* =========================
   AUTO RESULT MIRROR
   Source: https://kolkataff.tv/
   This mirrors published Patti + Single into Today's Result.
   It intentionally does NOT settle/pay bets; settlement remains controlled
   by the existing admin result route.
========================= */

const AUTO_RESULT_SOURCE_URL = "https://kolkataff.tv/";

function stripHtml(value) {
  return String(value || "")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/\s+/g, " ")
    .trim();
}

function indiaDateWords() {
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Asia/Kolkata",
    day: "2-digit",
    month: "long",
    year: "numeric"
  }).formatToParts(new Date());
  const o = Object.fromEntries(parts.map(p => [p.type, p.value]));
  return { day: String(Number(o.day)), month: o.month, year: o.year };
}

function sourceIndiaDateKeyFromHtml(html) {
  const live = String(html || "").split(/OLD\s+RESULTS/i)[0];
  const text = stripHtml(live);
  const m = text.match(/\b(\d{1,2})\s+(JANUARY|FEBRUARY|MARCH|APRIL|MAY|JUNE|JULY|AUGUST|SEPTEMBER|OCTOBER|NOVEMBER|DECEMBER)\s+(\d{4})\b/i);
  if (!m) return "";
  const months = {
    JANUARY:"01",FEBRUARY:"02",MARCH:"03",APRIL:"04",MAY:"05",JUNE:"06",
    JULY:"07",AUGUST:"08",SEPTEMBER:"09",OCTOBER:"10",NOVEMBER:"11",DECEMBER:"12"
  };
  return `${m[3]}-${months[m[2].toUpperCase()]}-${String(Number(m[1])).padStart(2,"0")}`;
}

function parseKolkataFfTodayHtml(html) {
  const raw = String(html || "");
  const beforeOld = raw.split(/OLD\s+RESULTS/i)[0];
  const sourceDay = sourceIndiaDateKeyFromHtml(beforeOld);
  const gameDay = currentGameDayKey();

  // Critical protection: stale CDN/server pages must NEVER overwrite today's
  // results. This was the reason old/wrong numbers could enter the site.
  if (!sourceDay || sourceDay !== gameDay) {
    throw new Error(`Source is stale (${sourceDay || "unknown"}), expected ${gameDay}.`);
  }

  // Limit parsing to the result area: after today's date heading and before
  // the source's Refresh button / old result section.
  let liveBlock = beforeOld;
  const dateHeading = liveBlock.search(/<h3\b[^>]*>[\s\S]*?\d{1,2}\s+[A-Za-z]+\s+\d{4}[\s\S]*?<\/h3>/i);
  if (dateHeading >= 0) liveBlock = liveBlock.slice(dateHeading);
  const refreshAt = liveBlock.search(/Refresh\s*Karo/i);
  if (refreshAt > 0) liveBlock = liveBlock.slice(0, refreshAt);

  // Current source renders Patti and Single as H4 values.
  const values = [];
  const h4Re = /<h4\b[^>]*>([\s\S]*?)<\/h4>/gi;
  let match;
  while ((match = h4Re.exec(liveBlock)) !== null) {
    const value = stripHtml(match[1]).replace(/\s/g, "");
    if (/^(?:\d{3}|\d|-)$/.test(value)) values.push(value);
    if (values.length >= 16) break;
  }

  const rows = [];
  for (let i = 0, baji = 1; i + 1 < values.length && baji <= 8; i += 2, baji++) {
    const patti = values[i];
    const single = values[i + 1];

    // "-" means that source slot has not published a result yet.
    if (patti === "-" || single === "-") continue;
    if (!/^\d{3}$/.test(patti) || !/^\d$/.test(single)) continue;

    rows.push({
      baji,
      patti,
      single,
      declared: true,
      resultAt: resultAtForBaji(baji)
    });
  }

  if (!rows.length) {
    throw new Error("No published result pairs found in today's LIVE block.");
  }
  return { sourceDay, rows };
}

let autoResultSyncRunning = false;
let autoResultLastError = "";
let autoResultLastCheck = null;
let autoResultLastCount = 0;

async function syncPublishedResultsFromKolkataFf() {
  if (autoResultSyncRunning) return;
  autoResultSyncRunning = true;
  autoResultLastCheck = new Date();
  try {
    let parsed = null;
    let lastFetchError = "";
    const urls = [
      `https://kolkataff.tv/?kf8_refresh=${Date.now()}`,
      `https://www.kolkataff.tv/?kf8_refresh=${Date.now()}`
    ];

    for (const sourceUrl of urls) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 12000);
      try {
        const response = await fetch(sourceUrl, {
          signal: controller.signal,
          redirect: "follow",
          cache: "no-store",
          headers: {
            "Accept": "text/html,application/xhtml+xml",
            "Cache-Control": "no-cache, no-store, max-age=0",
            "Pragma": "no-cache",
            "User-Agent": "Mozilla/5.0 (Linux; Android 11) AppleWebKit/537.36 Chrome/140.0 Mobile Safari/537.36"
          }
        });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const html = await response.text();
        if (html.length > 2_000_000) throw new Error("Source response too large.");
        parsed = parseKolkataFfTodayHtml(html);
        if (parsed?.rows?.length) break;
      } catch (err) {
        lastFetchError = String(err?.message || err);
      } finally {
        clearTimeout(timer);
      }
    }

    if (!parsed?.rows?.length) {
      throw new Error(lastFetchError || "No valid current-day source response.");
    }

    const published = parsed.rows;
    autoResultLastCount = published.length;
    autoResultLastError = "";
    if (!published.length) return;

    const current = await getResults();
    const next = current.map(row => {
      const incoming = published.find(x => Number(x.baji) === Number(row.baji));
      return incoming ? incoming : row;
    });

    const changed = next.some((r, i) =>
      Boolean(r.declared) !== Boolean(current[i]?.declared) ||
      String(r.patti) !== String(current[i]?.patti) ||
      String(r.single) !== String(current[i]?.single)
    );
    if (!changed) return;

    const changedRows = next.filter((r, i) =>
      Boolean(r.declared) &&
      (
        !Boolean(current[i]?.declared) ||
        String(r.patti) !== String(current[i]?.patti) ||
        String(r.single) !== String(current[i]?.single)
      )
    );

    await Result.findOneAndUpdate(
      { key: "main" },
      {
        $set: {
          dayKey: currentGameDayKey(),
          results: next,
          sourceUpdatedAt: new Date(),
          sourceName: "kolkataff.tv"
        }
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    // Settle only newly published/changed Baji rows. Bets are Pending-only,
    // so the same bet cannot be rewarded twice on repeated syncs.
    let totalWinners = 0;
    for (const row of changedRows) {
      totalWinners += await settleBajiFromAutoSource(
        Number(row.baji),
        String(row.patti),
        String(row.single)
      );
    }

    broadcast("results", { results: next, source: "kolkataff.tv" });
    broadcast("admin-data", { type: "auto-results-updated", source: "kolkataff.tv" });
    console.log(`[AUTO RESULT] Mirrored ${published.length} published Baji result(s) from kolkataff.tv and settled ${totalWinners || 0} winner(s)`);
  } catch (error) {
    autoResultLastError = String(error?.message || error);
    console.warn("[AUTO RESULT] Sync skipped:", autoResultLastError);
  } finally {
    autoResultSyncRunning = false;
  }
}


async function seedVerifiedAug18ResultsIfEmpty() {
  if (currentGameDayKey() !== "2026-08-18") return;

  // Exact values visible on the user's live kolkataff.tv screenshot
  // at 18:51 IST on 18 Aug 2026. These replace stale/local demo values.
  const verified = [
    { baji:1, patti:"369", single:"8", declared:true, resultAt:resultAtForBaji(1) },
    { baji:2, patti:"134", single:"8", declared:true, resultAt:resultAtForBaji(2) },
    { baji:3, patti:"370", single:"0", declared:true, resultAt:resultAtForBaji(3) },
    { baji:4, patti:"499", single:"2", declared:true, resultAt:resultAtForBaji(4) },
    { baji:5, patti:"680", single:"4", declared:true, resultAt:resultAtForBaji(5) },
    { baji:6, patti:"678", single:"1", declared:true, resultAt:resultAtForBaji(6) }
  ];

  const current = await getResults();

  // Force-correct Baji 1-6. Baji 7/8 remain waiting until the live source
  // publishes them. This removes the old 239/147/578/etc demo results.
  const next = current.map(row => {
    const exact = verified.find(v => v.baji === Number(row.baji));
    if (exact) return exact;
    if (Number(row.baji) >= 7) {
      return {
        baji:Number(row.baji),
        patti:"---",
        single:"-",
        declared:false,
        resultAt:resultAtForBaji(Number(row.baji))
      };
    }
    return row;
  });

  const changedRows = verified.filter(v => {
    const old = current.find(r => Number(r.baji) === v.baji);
    return !old?.declared || String(old.patti) !== v.patti || String(old.single) !== v.single;
  });

  await Result.findOneAndUpdate(
    { key:"main" },
    {
      $set:{
        dayKey:currentGameDayKey(),
        results:next,
        sourceUpdatedAt:new Date(),
        sourceName:"kolkataff.tv (verified live screenshot)"
      }
    },
    { upsert:true, new:true }
  );

  // Only currently Pending bets can settle, so this cannot pay the same bet twice.
  for (const row of changedRows) {
    await settleBajiFromAutoSource(row.baji, row.patti, row.single);
  }

  broadcast("results", { results:next, source:"kolkataff.tv" });
}

// Check periodically because the source publishes multiple results through the day.
setInterval(syncPublishedResultsFromKolkataFf, 15 * 1000).unref?.();
setTimeout(() => {
  seedVerifiedAug18ResultsIfEmpty()
    .then(() => syncPublishedResultsFromKolkataFf())
    .catch(err => console.warn("[AUTO RESULT] startup:", err?.message || err));
}, 1500).unref?.();

/* =========================
   HEALTH
========================= */

const publicDir = path.join(__dirname, "public");
app.use(express.static(publicDir, { extensions: ["html"], index: false }));
app.get("/", (req, res) => res.sendFile(path.join(publicDir, "index.html")));
app.get("/admin", (req, res) => res.sendFile(path.join(publicDir, "admin.html")));

app.get("/api/health", async (req, res) => {
  try {
    await mongoose.connection.db.admin().ping();
    res.json({ success: true, database: "connected" });
  } catch (_) {
    res.status(503).json({ success: false, database: "disconnected" });
  }
});

/* =========================
   AUTH
========================= */

async function registerHandler(req, res) {
  try {
    const username = cleanUsername(req.body.username || req.body.userName);
    const email = cleanEmail(req.body.email);
    const password = String(req.body.password || "");

    if (!/^[A-Za-z0-9._-]{3,24}$/.test(username)) {
      return res.status(400).json({ success: false, message: "Username must be 3-24 characters." });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ success: false, message: "Enter a valid email." });
    }

    if (password.length < 10 || password.length > 128 || !/[A-Za-z]/.test(password) || !/\d/.test(password)) {
      return res.status(400).json({ success:false, message:"Password must be 10-128 characters and include letters and a number." });
    }

    const existing = await User.findOne({
      $or: [{ username }, { email }]
    });

    if (existing) {
      return res.status(409).json({ success: false, message: "Username or email already exists." });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = await User.create({
      username,
      email,
      password: hashedPassword,
      balance: 0,
      role: "user",
      isAdmin: false
    });

    const token = makeToken(user);
    res.status(201).json({
      success: true,
      message: "User registered successfully.",
      token,
      user: publicUser(user)
    });
  } catch (error) {
    console.error("REGISTER ERROR:", error);
    res.status(500).json({ success: false, message: "Registration failed." });
  }
}

app.post("/register", registerHandler);
app.post("/api/auth/register", registerHandler);

async function loginHandler(req, res) {
  try {
    const identity = cleanUsername(req.body.username || req.body.email || req.body.identity);
    const password = String(req.body.password || "");

    if (!identity || !password) {
      return res.status(400).json({ success: false, message: "Username/email and password are required." });
    }

    const user = await User.findOne({
      $or: [
        { username: identity },
        { email: cleanEmail(identity) }
      ]
    }).select("+tokenVersion");

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ success: false, message: "Invalid username/email or password." });
    }

    const token = makeToken(user);
    res.json({
      success: true,
      message: "Login successful.",
      token,
      user: publicUser(user)
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);
    res.status(500).json({ success: false, message: "Login failed." });
  }
}

app.post("/login", loginLimiter, loginHandler);
app.post("/api/auth/login", loginLimiter, loginHandler);

app.get("/api/auth/me", auth, async (req, res) => {
  const user = await User.findById(req.auth.id);
  if (!user) return res.status(404).json({ success: false, message: "User not found." });
  res.json({ success: true, user: publicUser(user) });
});

async function adminUnlockHandler(req, res) {
  try {
    const password = String(req.body.password || "");
    if (!password) return res.status(400).json({ success: false, message: "Admin password is required." });

    const envUsername = cleanUsername(process.env.ADMIN_USERNAME);
    const query = envUsername
      ? { username: envUsername }
      : { $or: [{ role: "admin" }, { isAdmin: true }] };
    const admin = await User.findOne(query).select("+tokenVersion");

    if (!admin || !(admin.role === "admin" || admin.isAdmin) || !(await bcrypt.compare(password, admin.password))) {
      return res.status(401).json({ success: false, message: "Incorrect admin password." });
    }

    const token = makeToken(admin);
    res.json({ success: true, message: "Admin verified.", token, user: publicUser(admin) });
  } catch (error) {
    console.error("ADMIN UNLOCK ERROR:", error);
    res.status(500).json({ success: false, message: "Admin verification failed." });
  }
}

// Canonical admin unlock endpoint + aliases for older hosted HTML builds.
app.post("/api/admin/unlock", adminUnlockLimiter, adminUnlockHandler);
app.post("/api/admin/verify", adminUnlockLimiter, adminUnlockHandler);
app.post("/admin/unlock", adminUnlockLimiter, adminUnlockHandler);

/* =========================
   PASSWORD RESET
========================= */

app.post("/api/auth/forgot-password", forgotLimiter, async (req, res) => {
  try {
    const email = cleanEmail(req.body.email);
    const user = await User.findOne({ email });

    // Do not reveal whether an email exists.
    if (!user) {
      return res.json({ success: true, message: "If the account exists, a verification code has been sent." });
    }

    const otp = String(crypto.randomInt(100000, 1000000));
    const otpHash = crypto.createHash("sha256").update(otp).digest("hex");

    user.resetOtpHash = otpHash;
    user.resetOtpExpires = new Date(Date.now() + 10 * 60 * 1000);
    user.resetOtpAttempts = 0;
    await user.save();

    if (!process.env.RESEND_API_KEY || !process.env.RESET_FROM_EMAIL) {
      console.warn("Password reset requested but RESEND_API_KEY/RESET_FROM_EMAIL is not configured.");
      return res.status(503).json({
        success: false,
        message: "Password recovery email is not configured on the backend yet."
      });
    }

    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: process.env.RESET_FROM_EMAIL,
        to: [email],
        subject: "Kolkata FF 8 - Password Reset OTP",
        text: `Your Kolkata FF 8 password reset OTP is ${otp}. This OTP expires in 10 minutes. If you did not request this, you can ignore this email.`
      })
    });

    if (!response.ok) {
      console.error("RESET EMAIL ERROR:", await response.text());
      return res.status(502).json({ success: false, message: "Unable to send the reset email." });
    }

    res.json({ success: true, message: "6-digit OTP sent to your registered Gmail. It expires in 10 minutes." });
  } catch (error) {
    console.error("FORGOT PASSWORD ERROR:", error);
    res.status(500).json({ success: false, message: "Password recovery failed." });
  }
});

app.post("/api/auth/reset-password", resetLimiter, async (req, res) => {
  try {
    const email = cleanEmail(req.body.email);
    const otp = String(req.body.otp || "").trim();
    const newPassword = String(req.body.newPassword || "");

    if (!email || !/^\d{6}$/.test(otp) || newPassword.length < 10 || newPassword.length > 128 || !/[A-Za-z]/.test(newPassword) || !/\d/.test(newPassword)) {
      return res.status(400).json({ success:false, message:"Invalid reset details." });
    }

    const otpHash = crypto.createHash("sha256").update(otp).digest("hex");
    const user = await User.findOne({ email }).select("+resetOtpHash +resetOtpExpires +resetOtpAttempts +tokenVersion");

    const expired = !user?.resetOtpExpires || user.resetOtpExpires <= new Date();
    const locked = Number(user?.resetOtpAttempts || 0) >= 5;
    let matches = false;
    if (user?.resetOtpHash && !expired && !locked) {
      const a = Buffer.from(String(user.resetOtpHash), "hex");
      const b = Buffer.from(String(otpHash), "hex");
      matches = a.length === b.length && crypto.timingSafeEqual(a, b);
    }
    if (!user || expired || locked || !matches) {
      if (user && !expired && !locked) {
        user.resetOtpAttempts = Number(user.resetOtpAttempts || 0) + 1;
        await user.save().catch(() => {});
      }
      return res.status(400).json({ success:false, message:"Invalid or expired verification code." });
    }

    user.password = await bcrypt.hash(newPassword, 12);
    user.resetOtpHash = null;
    user.resetOtpExpires = null;
    user.resetOtpAttempts = 0;
    user.tokenVersion = Number(user.tokenVersion || 0) + 1; // logout every existing session
    await user.save();

    res.json({ success: true, message: "Password reset successfully." });
  } catch (error) {
    console.error("RESET PASSWORD ERROR:", error);
    res.status(500).json({ success: false, message: "Password reset failed." });
  }
});

/* =========================
   REAL-TIME EVENTS
========================= */

app.get("/api/events", async (req, res) => {
  const token = String(req.query.token || "");
  if (!token) return res.status(401).end();

  let decoded;
  try {
    decoded = jwt.verify(token, JWT_SECRET, { algorithms:["HS256"], issuer:JWT_ISSUER, audience:JWT_AUDIENCE });
    const liveUser = await User.findById(decoded.id).select("_id +tokenVersion");
    if (!liveUser || Number(decoded.v || 0) !== Number(liveUser.tokenVersion || 0)) return res.status(401).end();
  } catch (_) {
    return res.status(401).end();
  }

  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders?.();

  const userId = String(decoded.id);
  if (!clients.has(userId)) clients.set(userId, new Set());
  clients.get(userId).add(res);

  res.write(`event: connected\ndata: ${JSON.stringify({ success: true })}\n\n`);

  try {
    const user = await User.findById(userId);
    if (user) sendEventToUser(userId, "account", { user: publicUser(user), history: historyView(user) });
    const results = await getResults();
    res.write(`event: results\ndata: ${JSON.stringify({ results })}\n\n`);
  } catch (_) {}

  const heartbeat = setInterval(() => {
    try { res.write(": heartbeat\n\n"); } catch (_) {}
  }, 20000);

  req.on("close", () => {
    clearInterval(heartbeat);
    const set = clients.get(userId);
    if (set) {
      set.delete(res);
      if (!set.size) clients.delete(userId);
    }
  });
});

/* =========================
   BALANCE + HISTORY
========================= */

app.get("/api/balance", auth, async (req, res) => {
  const user = await User.findById(req.auth.id);
  if (!user) return res.status(404).json({ success: false, message: "User not found." });
  res.json({ success: true, balance: Number(user.balance || 0), pts: Number(user.balance || 0) });
});

app.get("/api/history", auth, async (req, res) => {
  const user = await User.findById(req.auth.id);
  if (!user) return res.status(404).json({ success: false, message: "User not found." });
  res.json({ success: true, ...historyView(user) });
});

app.get("/api/ledger", auth, async (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 200);
  const entries = await Ledger.find({ userId: req.auth.id })
    .sort({ createdAt: -1 })
    .limit(limit)
    .lean();
  res.json({ success: true, entries });
});

app.get("/api/admin/audit-log", auth, adminOnly, async (req, res) => {
  const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 500);
  const entries = await AuditLog.find({})
    .sort({ createdAt: -1 })
    .limit(limit)
    .lean();
  res.json({ success: true, entries });
});


// Kept only as a compatibility route; it still requires the logged-in user.
app.get("/history/:email", auth, async (req, res) => {
  const requested = cleanEmail(req.params.email);
  const user = await User.findById(req.auth.id);
  if (!user || user.email !== requested) {
    return res.status(403).json({ success: false, message: "You can only view your own history." });
  }
  res.json({ success: true, ...historyView(user) });
});

/* =========================
   DEPOSIT REQUESTS
========================= */

app.post("/api/deposit", auth, async (req, res) => {
  try {
    const amount = cleanAmount(req.body.amount);
    const utr = String(req.body.utr || req.body.UTR || req.body.transactionId || "").trim();

    if (!amount || amount < 100 || utr.length < 6) {
      return res.status(400).json({ success: false, message: "Minimum demo deposit is 100 PTS and a valid reference is required." });
    }

    const duplicateUtr = await User.findOne({
      _id: req.auth.id,
      depositHistory: { $elemMatch: { utr, status: { $in: ["Pending", "Approved"] } } }
    }).lean();
    if (duplicateUtr) {
      return res.status(409).json({ success: false, message: "This demo deposit reference has already been used." });
    }

    const user = await User.findById(req.auth.id);
    if (!user) return res.status(404).json({ success: false, message: "User not found." });

    if (!Array.isArray(user.depositHistory)) user.depositHistory = [];
    if (!Array.isArray(user.transactionHistory)) user.transactionHistory = [];

    const requestId = new mongoose.Types.ObjectId().toString();
    const item = {
      id: requestId,
      type: "Deposit",
      amount,
      utr,
      status: "Pending",
      details: "UPI deposit request",
      date: new Date()
    };

    user.depositHistory.unshift(item);
    user.transactionHistory.unshift(item);
    await user.save();

    sendEventToUser(user._id, "account", { user: publicUser(user), history: historyView(user) });
    broadcast("admin-data", { type: "deposit-created" });

    res.status(201).json({
      success: true,
      message: "Deposit request submitted.",
      request: item,
      balance: Number(user.balance || 0),
      user: publicUser(user),
      history: historyView(user)
    });
  } catch (error) {
    console.error("DEPOSIT ERROR:", error);
    res.status(500).json({ success: false, message: "Deposit request failed." });
  }
});

/* =========================
   WITHDRAWAL REQUESTS
========================= */

app.post("/api/withdrawal", auth, async (req, res) => {
  try {
    const amount = cleanAmount(req.body.amount);
    const upi = String(req.body.upi || req.body.upiId || "").trim();

    if (!amount || amount < 100 || !upi) {
      return res.status(400).json({ success: false, message: "Minimum demo withdrawal is 100 PTS and a valid UPI ID is required." });
    }

    const user = await User.findById(req.auth.id);
    if (!user) return res.status(404).json({ success: false, message: "User not found." });

    if (Number(user.winningBalance || 0) < amount) {
      return res.status(400).json({ success:false, message:`Only winning balance can be withdrawn. Withdrawable balance: ₹${Number(user.winningBalance || 0).toFixed(2)}` });
    }

    const pendingWithdrawal = (user.withdrawalHistory || []).find(
      x => String(x.status).toLowerCase() === "pending"
    );
    if (pendingWithdrawal) {
      return res.status(409).json({ success: false, message: "A demo withdrawal is already pending." });
    }

    user.balance = Number((Number(user.balance || 0) - amount).toFixed(2));
    user.winningBalance = Number((Number(user.winningBalance || 0) - amount).toFixed(2));

    if (!Array.isArray(user.withdrawalHistory)) user.withdrawalHistory = [];
    if (!Array.isArray(user.transactionHistory)) user.transactionHistory = [];

    const requestId = new mongoose.Types.ObjectId().toString();
    // Deliberately do NOT store UTR/transactionId for withdrawals.
    const item = {
      id: requestId,
      type: "Withdrawal",
      amount,
      upi,
      status: "Pending",
      details: "UPI withdrawal request",
      date: new Date()
    };

    user.withdrawalHistory.unshift(item);
    user.transactionHistory.unshift(item);
    await user.save();

    sendEventToUser(user._id, "account", { user: publicUser(user), history: historyView(user) });
    broadcast("admin-data", { type: "withdrawal-created" });

    res.status(201).json({
      success: true,
      message: "Withdrawal request submitted.",
      request: item,
      balance: Number(user.balance || 0),
      user: publicUser(user),
      history: historyView(user)
    });
  } catch (error) {
    console.error("WITHDRAW ERROR:", error);
    res.status(500).json({ success: false, message: "Withdrawal request failed." });
  }
});


/* Game entry lock: block bets after closing time */
const BAJI_CLOSE_MINUTES = {
  1: 10 * 60,
  2: 11 * 60 + 30,
  3: 13 * 60,
  4: 14 * 60 + 30,
  5: 16 * 60,
  6: 17 * 60 + 30,
  7: 19 * 60,
  8: 20 * 60 + 30
};

function indiaClockMinutes() {
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Asia/Kolkata", hour: "2-digit", minute: "2-digit", hourCycle: "h23"
  }).formatToParts(new Date());
  const hour = Number(parts.find(p => p.type === "hour")?.value || 0);
  const minute = Number(parts.find(p => p.type === "minute")?.value || 0);
  return hour * 60 + minute;
}

function isGameClosed(baji) {
  const closeMinutes = BAJI_CLOSE_MINUTES[Number(baji)];
  if (!Number.isFinite(closeMinutes)) return true;
  return indiaClockMinutes() >= closeMinutes;
}


/* =========================
   PRACTICE SINGLE + PATTI API
   Database-backed virtual points only.
========================= */

async function practiceAccountHandler(req, res) {
  try {
    const user = await User.findById(req.auth.id);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found." });
    }

    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
    const payload = await practiceAccountPayload(user);

    return res.json({
      success: true,
      ...payload
    });
  } catch (error) {
    console.error("PRACTICE ACCOUNT ERROR:", error);
    return res.status(500).json({
      success: false,
      message: "Practice Wallet could not be loaded."
    });
  }
}

app.get("/api/practice/account", auth, practiceAccountHandler);
app.get("/api/practice/patti/account", auth, practiceAccountHandler);

app.post("/api/practice/single/bets", auth, async (req, res) => {
  try {
    const baji = Number(req.body.baji);
    const digit = String(req.body.digit ?? req.body.rawTarget ?? "").trim();
    const stake = cleanAmount(req.body.stake);
    const clientRequestId = cleanPracticeRequestId(req.body.clientRequestId);

    if (!clientRequestId) {
      return res.status(400).json({
        success: false,
        message: "Practice request id is missing. Please retry."
      });
    }

    if (!Number.isInteger(baji) || baji < 1 || baji > 8) {
      return res.status(400).json({ success: false, message: "Invalid Baji." });
    }

    if (!/^\d$/.test(digit)) {
      return res.status(400).json({
        success: false,
        message: "Select a valid Single Digit."
      });
    }

    if (!stake) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid stake."
      });
    }

    const user = await User.findById(req.auth.id);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found." });
    }

    let existing = await PracticeSingleBet.findOne({
      userId: user._id,
      clientRequestId
    });

    if (existing) {
      const payload = await practicePayloadBestEffort(user);
      return res.status(200).json({
        success: true,
        duplicateSafeRetry: true,
        message: `Single ${existing.digit} practice entry already saved.`,
        bet: existing,
        ...payload
      });
    }

    if (isGameClosed(baji)) {
      return res.status(403).json({
        success: false,
        message: `Baji ${baji} is closed.`
      });
    }

    await ensurePracticeWallet(user);

    const walletAfterDeduction = await PracticeWallet.findOneAndUpdate(
      {
        userId: user._id,
        balance: { $gte: stake }
      },
      {
        $inc: { balance: -stake },
        $set: { username: user.username }
      },
      { new: true }
    );

    if (!walletAfterDeduction) {
      return res.status(400).json({
        success: false,
        message: "Insufficient Practice Wallet balance."
      });
    }

    let bet;

    try {
      bet = await PracticeSingleBet.create({
        userId: user._id,
        username: user.username,
        baji,
        gameDay: currentGameDayKey(),
        digit,
        stake,
        multiplier: 9,
        payout: Number((stake * 9).toFixed(2)),
        status: "Pending",
        walletCredited: false,
        clientRequestId
      });
    } catch (err) {
      await PracticeWallet.updateOne(
        { userId: user._id },
        { $inc: { balance: stake } }
      );

      if (err?.code === 11000) {
        existing = await PracticeSingleBet.findOne({
          userId: user._id,
          clientRequestId
        });

        if (existing) {
          const payload = await practicePayloadBestEffort(user);
          return res.status(200).json({
            success: true,
            duplicateSafeRetry: true,
            message: `Single ${existing.digit} practice entry already saved.`,
            bet: existing,
            ...payload
          });
        }
      }

      throw err;
    }

    const payload = await practicePayloadBestEffort(user, walletAfterDeduction);
    void notifyPracticeUser(user._id);

    return res.status(201).json({
      success: true,
      message: `Single ${digit} practice entry saved.`,
      bet,
      ...payload
    });
  } catch (error) {
    console.error("PRACTICE SINGLE BET ERROR:", error);
    return res.status(500).json({
      success: false,
      message: "Practice Single entry could not be saved."
    });
  }
});

app.post("/api/practice/patti/bets", auth, async (req, res) => {
  try {
    const baji = Number(req.body.baji);
    const patti = String(req.body.patti ?? req.body.rawTarget ?? "").trim();
    const selectedDigit = String(req.body.digit ?? "").trim();
    const stake = cleanAmount(req.body.stake);
    const clientRequestId = cleanPracticeRequestId(req.body.clientRequestId);

    if (!clientRequestId) {
      return res.status(400).json({
        success: false,
        message: "Practice request id is missing. Please retry."
      });
    }

    if (!Number.isInteger(baji) || baji < 1 || baji > 8) {
      return res.status(400).json({ success: false, message: "Invalid Baji." });
    }

    if (!stake) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid stake."
      });
    }

    if (!/^\d{3}$/.test(patti) || !isValid220Patti(patti)) {
      return res.status(400).json({
        success: false,
        message: "Select a valid Patti from the fixed chart."
      });
    }

    const user = await User.findById(req.auth.id);
    if (!user) {
      return res.status(404).json({ success: false, message: "User not found." });
    }

    let existing = await PracticePattiBet.findOne({
      userId: user._id,
      clientRequestId
    });

    if (existing) {
      const payload = await practicePayloadBestEffort(user);
      return res.status(200).json({
        success: true,
        duplicateSafeRetry: true,
        message: `Patti ${existing.patti} practice entry already saved.`,
        bet: existing,
        ...payload
      });
    }

    if (isGameClosed(baji)) {
      return res.status(403).json({
        success: false,
        message: `Baji ${baji} is closed.`
      });
    }

    const requiredDigit = String(pattiSingle(patti) ?? "");

    if (selectedDigit && selectedDigit !== requiredDigit) {
      return res.status(400).json({
        success: false,
        message: `Patti ${patti} belongs under Single ${requiredDigit}.`
      });
    }

    const matchingSingle = await PracticeSingleBet.findOne({
      userId: user._id,
      baji,
      gameDay: currentGameDayKey(),
      digit: requiredDigit,
      status: "Pending"
    }).sort({ createdAt: -1 });

    if (!matchingSingle) {
      return res.status(409).json({
        success: false,
        message: `First place Single ${requiredDigit}, then place Patti ${patti}.`
      });
    }

    await ensurePracticeWallet(user);

    const walletAfterDeduction = await PracticeWallet.findOneAndUpdate(
      {
        userId: user._id,
        balance: { $gte: stake }
      },
      {
        $inc: { balance: -stake },
        $set: { username: user.username }
      },
      { new: true }
    );

    if (!walletAfterDeduction) {
      return res.status(400).json({
        success: false,
        message: "Insufficient Practice Wallet balance."
      });
    }

    let bet;

    try {
      bet = await PracticePattiBet.create({
        userId: user._id,
        username: user.username,
        baji,
        gameDay: currentGameDayKey(),
        patti,
        stake,
        multiplier: 90,
        payout: Number((stake * 90).toFixed(2)),
        status: "Pending",
        walletCredited: false,
        pairSingleBetId: matchingSingle._id,
        clientRequestId
      });
    } catch (err) {
      await PracticeWallet.updateOne(
        { userId: user._id },
        { $inc: { balance: stake } }
      );

      if (err?.code === 11000) {
        existing = await PracticePattiBet.findOne({
          userId: user._id,
          clientRequestId
        });

        if (existing) {
          const payload = await practicePayloadBestEffort(user);
          return res.status(200).json({
            success: true,
            duplicateSafeRetry: true,
            message: `Patti ${existing.patti} practice entry already saved.`,
            bet: existing,
            ...payload
          });
        }
      }

      throw err;
    }

    const payload = await practicePayloadBestEffort(user, walletAfterDeduction);
    void notifyPracticeUser(user._id);

    return res.status(201).json({
      success: true,
      message: `Patti ${patti} practice entry saved.`,
      bet,
      ...payload
    });
  } catch (error) {
    console.error("PRACTICE PATTI BET ERROR:", error);
    return res.status(500).json({
      success: false,
      message: "Practice Patti entry could not be saved."
    });
  }
});

/* =========================
   BETS
========================= */

app.post("/api/bets", auth, async (req, res) => {
  try {
    const baji = Number(req.body.baji);
    if (isGameClosed(baji)) {
      return res.status(403).json({ success: false, message: `Baji ${baji} is closed. Entry is not allowed now.` });
    }
    const betType = String(req.body.betType || "").toLowerCase();
    const rawTarget = String(req.body.rawTarget ?? req.body.target ?? "").trim();
    const stake = cleanAmount(req.body.stake);

    const multipliers = { single: 9, patti: 90, jodi: 90 };
    if (!Number.isInteger(baji) || baji < 1 || baji > 8 || !multipliers[betType] || !stake || !rawTarget) {
      return res.status(400).json({ success: false, message: "Invalid bet details." });
    }

    if (
      (betType === "single" && !/^\d$/.test(rawTarget)) ||
      (betType === "patti" && (!/^\d{3}$/.test(rawTarget) || !isValid220Patti(rawTarget))) ||
      (betType === "jodi" && !/^\d{2}$/.test(rawTarget))
    ) {
      return res.status(400).json({ success: false, message: betType === "patti" ? "Select a valid Patti from the fixed 220 Patti chart." : "Invalid target." });
    }

    const user = await User.findById(req.auth.id);
    if (!user) return res.status(404).json({ success: false, message: "User not found." });

    if (Number(user.balance || 0) < stake) {
      return res.status(400).json({ success: false, message: "Insufficient balance." });
    }

    user.balance = Number((Number(user.balance || 0) - stake).toFixed(2));
    user.totalPredictions = Number(user.totalPredictions || 0) + 1;
    user.totalBet = Number((Number(user.totalBet || 0) + stake).toFixed(2));

    const multiplier = multipliers[betType];
    const bet = await Bet.create({
      userId: user._id,
      username: user.username,
      baji,
      gameDay: currentGameDayKey(),
      betType,
      rawTarget,
      stake,
      multiplier,
      payout: Number((stake * multiplier).toFixed(2))
    });

    if (!Array.isArray(user.transactionHistory)) user.transactionHistory = [];
    if (!Array.isArray(user.gameHistory)) user.gameHistory = [];
    const gameHistoryItem = {
      id: String(bet._id),
      type: "Bet Placed",
      amount: -stake,
      status: "Pending",
      baji,
      betType,
      rawTarget,
      stake,
      payout: bet.payout,
      details: `Kolkata FF 8 Baji ${baji}`,
      date: new Date()
    };
    // Store the same activity in the general ledger-style history and in a
    // dedicated permanent game history for the user's profile.
    user.transactionHistory.unshift(gameHistoryItem);
    user.gameHistory.unshift({ ...gameHistoryItem });

    await user.save();
    await recordLedger(user, "DEMO_BET", -stake, String(bet._id), {
      baji, betType, target: rawTarget, demo: true
    });
    await notifyUser(user);

    res.status(201).json({
      success: true,
      message: "Bet placed.",
      bet,
      user: publicUser(user),
      history: historyView(user)
    });
  } catch (error) {
    console.error("BET ERROR:", error);
    res.status(500).json({ success: false, message: "Bet could not be placed." });
  }
});

/* =========================
   RESULTS
========================= */

app.get("/api/results", async (req, res) => {
  const results = await getResults();
  res.json({ success: true, results });
});

app.get("/api/latest-results", async (req, res) => {
  const results = await getResults();
  res.json({ success: true, results });
});

app.get("/api/result-source-status", async (req, res) => {
  const doc = await Result.findOne({ key: "main" }).select("dayKey sourceUpdatedAt sourceName results").lean();
  res.json({
    success: true,
    source: doc?.sourceName || "kolkataff.tv",
    sourceUpdatedAt: doc?.sourceUpdatedAt || null,
    lastCheck: autoResultLastCheck,
    lastError: autoResultLastError || null,
    sourcePublishedCount: autoResultLastCount,
    dayKey: doc?.dayKey || currentGameDayKey(),
    displayedCount: Array.isArray(doc?.results) ? doc.results.filter(x => x.declared).length : 0
  });
});

app.get("/api/live-result-sync-status", async (req, res) => {
  const doc = await Result.findOne({ key:"main" })
    .select("dayKey sourceUpdatedAt sourceName results")
    .lean();
  res.json({
    success:true,
    gameDay:currentGameDayKey(),
    source:doc?.sourceName || null,
    sourceUpdatedAt:doc?.sourceUpdatedAt || null,
    lastCheck:autoResultLastCheck,
    lastError:autoResultLastError || null,
    displayed:(doc?.results || []).filter(r => r.declared).map(r => ({
      baji:Number(r.baji),
      patti:String(r.patti),
      single:String(r.single)
    }))
  });
});


app.post("/api/admin/sync-source-results", auth, adminOnly, async (req, res) => {
  await syncPublishedResultsFromKolkataFf();
  const results = await getResults();
  res.json({
    success: !autoResultLastError,
    message: autoResultLastError ? `Source sync failed: ${autoResultLastError}` : "Source results synced.",
    results,
    lastCheck: autoResultLastCheck,
    sourcePublishedCount: autoResultLastCount
  });
});


async function settleBajiFromAutoSource(baji, patti, single) {
  const dayKey = currentGameDayKey();
  const [y,m,d] = dayKey.split("-").map(Number);
  const start = new Date(Date.UTC(y, m - 1, d, 2, 30, 0));
  const end = new Date(start.getTime() + 86400000);

  const bets = await Bet.find({
    baji,
    status: "Pending",
    $or: [
      { gameDay: dayKey },
      { gameDay: { $in: ["", null] }, createdAt: { $gte: start, $lt: end } }
    ]
  });

  let winners = 0;
  for (const bet of bets) {
    let won = false;
    if (bet.betType === "single") won = String(bet.rawTarget) === String(single);
    if (bet.betType === "patti") won = String(bet.rawTarget) === String(patti);
    if (bet.betType === "jodi") won = false;

    const user = await User.findById(bet.userId);
    if (!user) continue;

    const payout = Number(bet.payout || 0);

    if (won) {
      // Auto-source reward behaves exactly like a normal game win.
      user.balance = Number((Number(user.balance || 0) + payout).toFixed(2));
      user.winningBalance = Number((Number(user.winningBalance || 0) + payout).toFixed(2));
      user.wins = Number(user.wins || 0) + 1;

      bet.status = "WON";
      bet.result = `${patti}/${single}`;
      bet.settledAt = new Date();

      const tx = (user.transactionHistory || []).find(x => String(x.id) === String(bet._id));
      if (tx) {
        tx.status = "WON";
        tx.amount = payout;
        tx.result = bet.result;
        tx.settledAt = bet.settledAt;
        tx.details = `Auto result win • ${bet.multiplier}x`;
      }

      const gx = (user.gameHistory || []).find(x => String(x.id) === String(bet._id));
      if (gx) {
        gx.status = "WON";
        gx.amount = payout;
        gx.result = bet.result;
        gx.settledAt = bet.settledAt;
        gx.details = `Auto result win • ${bet.multiplier}x`;
      }

      winners++;
    } else {
      user.losses = Number(user.losses || 0) + 1;

      bet.status = "LOST";
      bet.result = `${patti}/${single}`;
      bet.settledAt = new Date();

      const tx = (user.transactionHistory || []).find(x => String(x.id) === String(bet._id));
      if (tx) {
        tx.status = "LOST";
        tx.result = bet.result;
        tx.settledAt = bet.settledAt;
        tx.details = "Auto result • Bet lost";
      }

      const gx = (user.gameHistory || []).find(x => String(x.id) === String(bet._id));
      if (gx) {
        gx.status = "LOST";
        gx.result = bet.result;
        gx.settledAt = bet.settledAt;
        gx.details = "Auto result • Bet lost";
      }
    }

    await user.save();

    if (won) {
      await recordLedger(user, "AUTO_WIN", payout, String(bet._id), {
        baji: bet.baji,
        betType: bet.betType,
        result: bet.result,
        source: "kolkataff.tv",
        withdrawable: true
      });
    }

    await bet.save();
    await notifyUser(user);
  }

  await settlePracticePattiBaji(baji, patti);
  return winners;
}

async function settleBaji(baji, patti, single) {
  const dayKey=currentGameDayKey();
  const [y,m,d]=dayKey.split("-").map(Number);
  const start=new Date(Date.UTC(y,m-1,d,2,30,0)), end=new Date(start.getTime()+86400000);
  const bets=await Bet.find({baji,status:"Pending",$or:[{gameDay:dayKey},{gameDay:{$in:["",null]},createdAt:{$gte:start,$lt:end}}]});
  let winners = 0;

  for (const bet of bets) {
    let won = false;

    if (bet.betType === "single") won = bet.rawTarget === single;
    if (bet.betType === "patti") won = bet.rawTarget === patti;
    // Jodi settlement is only possible if a 2-digit jodi is supplied with the result.
    if (bet.betType === "jodi") won = false;

    const user = await User.findById(bet.userId);
    if (!user) continue;

    const historyItem = user.transactionHistory.id ? user.transactionHistory.id(String(bet._id)) : null;

    if (won) {
      user.balance = Number((Number(user.balance || 0) + Number(bet.payout || 0)).toFixed(2));
      user.winningBalance = Number((Number(user.winningBalance || 0) + Number(bet.payout || 0)).toFixed(2));
      user.wins = Number(user.wins || 0) + 1;
      bet.status = "WON";
      bet.result = `${patti}/${single}`;
      bet.settledAt = new Date();

      const tx = user.transactionHistory.find(x => String(x.id) === String(bet._id));
      if (tx) {
        tx.status = "WON";
        tx.amount = Number(bet.payout || 0);
        tx.details = `Won ${bet.multiplier}x`;
      }
      const gx = (user.gameHistory || []).find(x => String(x.id) === String(bet._id));
      if (gx) {
        gx.status = "WON";
        gx.amount = Number(bet.payout || 0);
        gx.details = `Won ${bet.multiplier}x`;
      }
      winners++;
    } else {
      user.losses = Number(user.losses || 0) + 1;
      bet.status = "LOST";
      bet.result = `${patti}/${single}`;
      bet.settledAt = new Date();

      const tx = user.transactionHistory.find(x => String(x.id) === String(bet._id));
      if (tx) {
        tx.status = "LOST";
        tx.details = "Bet lost";
      }
      const gx = (user.gameHistory || []).find(x => String(x.id) === String(bet._id));
      if (gx) {
        gx.status = "LOST";
        gx.details = "Bet lost";
      }
    }

    await user.save();
    if (won) {
      await recordLedger(user, "DEMO_WIN", Number(bet.payout || 0), String(bet._id), {
        baji: bet.baji, betType: bet.betType, result: bet.result, demo: true
      });
    }
    await bet.save();
    await notifyUser(user);
  }

  await settlePracticePattiBaji(baji, patti);
  return winners;
}

app.post("/api/admin/results", auth, adminOnly, async (req, res) => {
  try {
    const baji = Number(req.body.baji);
    const patti = String(req.body.patti || "").replace(/\D/g, "").slice(0, 3);
    const single = pattiSingle(patti);

    if (!Number.isInteger(baji) || baji < 1 || baji > 8 || patti.length !== 3 || !isValid220Patti(patti) || single === null) {
      return res.status(400).json({ success: false, message: "Choose a valid Patti from the fixed 220 Patti chart. Single is calculated automatically." });
    }

    const current = await getResults();
    const next = current.map((r, i) =>
      Number(r.baji) === baji
        ? { baji, patti, single, declared: true, resultAt: String(r.resultAt || resultAtForBaji(baji)) }
        : { ...r, baji: Number(r.baji || i + 1) }
    );

    await Result.findOneAndUpdate(
      { key: "main" },
      { $set: { dayKey: currentGameDayKey(), results: next } },
      { upsert: true, new: true }
    );

    const winners = await settleBaji(baji, patti, single);

    broadcast("results", { results: next });
    broadcast("admin-data", { type: "result-updated", baji });

    res.json({
      success: true,
      message: `Baji ${baji} result updated.`,
      results: next,
      winners
    });
  } catch (error) {
    console.error("ADMIN RESULT ERROR:", error);
    res.status(500).json({ success: false, message: "Result update failed." });
  }
});

app.post("/api/admin/latest-results", auth, adminOnly, async (req, res) => {
  try {
    const rows = normalizeResults(req.body.results);
    if (!rows) return res.status(400).json({ success: false, message: "Exactly 8 valid results are required." });

    const previous = await getResults();
    await Result.findOneAndUpdate(
      { key: "main" },
      { $set: { dayKey: currentGameDayKey(), results: rows } },
      { upsert: true, new: true }
    );
    for (const row of rows) {
      const old = previous.find(x => Number(x.baji) === Number(row.baji));
      if (!old?.declared || old.patti !== row.patti || old.single !== row.single) {
        await settleBaji(Number(row.baji), String(row.patti), String(row.single));
      }
    }
    broadcast("results", { results: rows });
    broadcast("admin-data", { type: "results-updated" });

    res.json({ success: true, results: rows });
  } catch (error) {
    console.error("LATEST RESULTS ERROR:", error);
    res.status(500).json({ success: false, message: "Latest results update failed." });
  }
});

/* =========================
   ADMIN DATA
========================= */

app.get("/api/admin/users", auth, adminOnly, async (req, res) => {
  const users = await User.find().select("-password -resetOtpHash -resetOtpExpires").sort({ createdAt: -1 });
  res.json({ success: true, totalUsers: users.length, users: users.map(publicUser) });
});

app.get("/admin/users", auth, adminOnly, async (req, res) => {
  const users = await User.find().select("-password -resetOtpHash -resetOtpExpires").sort({ createdAt: -1 });
  res.json({ success: true, totalUsers: users.length, users });
});

app.get("/api/admin/deposits", auth, adminOnly, async (req, res) => {
  const users = await User.find().select("username email depositHistory");
  const requests = [];
  for (const user of users) {
    for (const item of user.depositHistory || []) {
      if (String(item.status).toLowerCase() === "pending") {
        requests.push({
          id: item.id,
          username: user.username,
          email: user.email,
          amount: Number(item.amount || 0),
          utr: item.utr || "",
          status: item.status,
          date: item.date
        });
      }
    }
  }
  requests.sort((a, b) => new Date(b.date) - new Date(a.date));
  res.json({ success: true, requests });
});

app.get("/api/admin/withdrawals", auth, adminOnly, async (req, res) => {
  const users = await User.find().select("username email withdrawalHistory");
  const requests = [];
  for (const user of users) {
    for (const item of user.withdrawalHistory || []) {
      if (String(item.status).toLowerCase() === "pending") {
        requests.push({
          id: item.id,
          username: user.username,
          email: user.email,
          amount: Number(item.amount || 0),
          upi: item.upi || "",
          status: item.status,
          date: item.date
        });
      }
    }
  }
  requests.sort((a, b) => new Date(b.date) - new Date(a.date));
  res.json({ success: true, requests });
});

// Compatibility aliases for older frontend builds.
app.get("/api/admin/deposit-requests", auth, adminOnly, async (req, res) => {
  const users = await User.find().select("username email depositHistory");
  const requests = [];
  for (const user of users) for (const item of user.depositHistory || []) {
    if (String(item.status).toLowerCase() === "pending") requests.push({
      id: item.id, username: user.username, email: user.email, amount: Number(item.amount || 0),
      utr: item.utr || "", status: item.status, date: item.date
    });
  }
  requests.sort((a,b)=>new Date(b.date)-new Date(a.date));
  res.json({success:true, requests});
});

app.get("/api/admin/withdrawal-requests", auth, adminOnly, async (req, res) => {
  const users = await User.find().select("username email withdrawalHistory");
  const requests = [];
  for (const user of users) for (const item of user.withdrawalHistory || []) {
    if (String(item.status).toLowerCase() === "pending") requests.push({
      id: item.id, username: user.username, email: user.email, amount: Number(item.amount || 0),
      upi: item.upi || "", status: item.status, date: item.date
    });
  }
  requests.sort((a,b)=>new Date(b.date)-new Date(a.date));
  res.json({success:true, requests});
});

async function findHistoryOwner(historyName, requestId) {
  // IMPORTANT: load the FULL user document. The old code selected only the
  // history array, which made user.balance look like 0 during admin approval.
  // That caused e.g. 400 + 300 to become 300.
  const user = await User.findOne({ [`${historyName}.id`]: String(requestId) });
  if (!user) return null;
  const item = (user[historyName] || []).find(x => String(x.id) === String(requestId));
  return item ? { user, item } : null;
}

app.post("/api/admin/deposits/:requestId", auth, adminOnly, async (req, res) => {
  try {
    const action = String(req.body.action || "").toLowerCase();
    if (!["approve", "reject"].includes(action)) {
      return res.status(400).json({ success: false, message: "Action must be approve or reject." });
    }

    const found = await findHistoryOwner("depositHistory", req.params.requestId);
    if (!found) return res.status(404).json({ success: false, message: "Deposit request not found." });

    const { user, item } = found;
    if (!Array.isArray(user.transactionHistory)) user.transactionHistory = [];
    if (!Array.isArray(user.depositHistory)) user.depositHistory = [];
    const currentStatus = String(item.status || "").toLowerCase();
    // Idempotent demo admin action: a second click on an already-approved
    // request must not add the amount a second time. It simply returns the
    // current saved balance instead of showing a red "already processed" error.
    if (currentStatus !== "pending") {
      if (action === "approve" && currentStatus === "approved") {
        return res.json({
          success: true,
          alreadyProcessed: true,
          message: "Deposit already approved; no duplicate credit was added.",
          user: publicUser(user),
          request: item
        });
      }
      return res.status(409).json({ success: false, message: "Deposit request already processed." });
    }

    if (action === "approve") {
      const before = Number(user.balance || 0);
      const amount = Number(item.amount || 0);
      // Demo points are additive: old balance is preserved and the approved
      // deposit is added on top (e.g. 400 + 300 = 700).
      user.balance = Number((before + amount).toFixed(2));
      item.status = "Approved";
      item.details = "Deposit approved by admin";
      item.reviewedAt = new Date();

      const tx = user.transactionHistory.find(x => String(x.id) === String(item.id));
      if (tx) {
        tx.status = "Approved";
        tx.details = "Deposit approved by admin";
      }
    } else {
      item.status = "Rejected";
      item.details = "Deposit rejected by admin";
      item.reviewedAt = new Date();

      const tx = user.transactionHistory.find(x => String(x.id) === String(item.id));
      if (tx) {
        tx.status = "Rejected";
        tx.details = "Deposit rejected by admin";
      }
    }

    await user.save();
    if (action === "approve") {
      await recordLedger(user, "DEMO_DEPOSIT", Number(item.amount || 0), String(item.id), {
        utr: item.utr || "", demo: true
      });
    }
    await writeAudit(req, `DEMO_DEPOSIT_${action.toUpperCase()}`, user, item.id, {
      amount: Number(item.amount || 0), demo: true
    });
    await notifyUser(user);
    broadcast("admin-data", { type: "deposit-processed" });

    res.json({ success: true, message: `Deposit ${action}ed.`, user: publicUser(user), request: item });
  } catch (error) {
    console.error("ADMIN DEPOSIT ERROR:", error);
    res.status(500).json({ success: false, message: "Deposit processing failed." });
  }
});

app.post("/api/admin/withdrawals/:requestId", auth, adminOnly, async (req, res) => {
  try {
    const action = String(req.body.action || "").toLowerCase();
    if (!["approve", "reject"].includes(action)) {
      return res.status(400).json({ success: false, message: "Action must be approve or reject." });
    }

    const found = await findHistoryOwner("withdrawalHistory", req.params.requestId);
    if (!found) return res.status(404).json({ success: false, message: "Withdrawal request not found." });

    const { user, item } = found;
    if (!Array.isArray(user.transactionHistory)) user.transactionHistory = [];
    if (!Array.isArray(user.withdrawalHistory)) user.withdrawalHistory = [];
    if (String(item.status).toLowerCase() !== "pending") {
      return res.status(409).json({ success: false, message: "Withdrawal request already processed." });
    }

    if (action === "reject") {
      user.balance = Number((Number(user.balance || 0) + Number(item.amount || 0)).toFixed(2));
      user.winningBalance = Number((Number(user.winningBalance || 0) + Number(item.amount || 0)).toFixed(2));
      item.status = "Rejected";
      item.details = "Withdrawal rejected; amount refunded";
      item.reviewedAt = new Date();

      const tx = user.transactionHistory.find(x => String(x.id) === String(item.id));
      if (tx) {
        tx.status = "Refunded";
        tx.details = "Withdrawal rejected; amount refunded";
        tx.amount = Number(item.amount || 0);
      }
    } else {
      item.status = "Approved";
      item.details = "Withdrawal approved by admin";
      item.reviewedAt = new Date();

      const tx = user.transactionHistory.find(x => String(x.id) === String(item.id));
      if (tx) {
        tx.status = "Approved";
        tx.details = "Withdrawal approved by admin";
      }
    }

    await user.save();
    if (action === "reject") {
      await recordLedger(user, "DEMO_WITHDRAWAL_REFUND", Number(item.amount || 0), String(item.id), {
        reason: "Admin rejected demo withdrawal; balance refunded", demo: true
      });
    }
    await writeAudit(req, `DEMO_WITHDRAWAL_${action.toUpperCase()}`, user, item.id, {
      amount: Number(item.amount || 0), demo: true
    });
    await notifyUser(user);
    broadcast("admin-data", { type: "withdrawal-processed" });

    res.json({ success: true, message: action === "approve" ? "Withdrawal approved." : "Withdrawal rejected.", user: publicUser(user), request: item });
  } catch (error) {
    console.error("ADMIN WITHDRAWAL ERROR:", error);
    res.status(500).json({ success: false, message: "Withdrawal processing failed." });
  }
});

/* =========================
   ADMIN PRACTICE PTS ADJUSTMENT
   Separate virtual Practice Wallet only.
   Never writes to user.balance, winningBalance or withdrawableBalance.
========================= */

app.post("/api/admin/practice-transfer", auth, adminOnly, async (req, res) => {
  try {
    const username = cleanUsername(req.body.username);
    const amount = cleanAmount(req.body.amount);
    const action = String(req.body.action || "add").toLowerCase();

    if (!username || !amount || !["add", "deduct"].includes(action)) {
      return res.status(400).json({
        success: false,
        message: "Username, valid amount and action are required."
      });
    }

    const escaped = username.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const user = await User.findOne({
      username: { $regex: new RegExp("^" + escaped + "$", "i") }
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found."
      });
    }

    await ensurePracticeWallet(user);

    let wallet;

    if (action === "deduct") {
      // Atomic check + deduction, so concurrent requests cannot push below zero.
      wallet = await PracticeWallet.findOneAndUpdate(
        {
          userId: user._id,
          balance: { $gte: amount }
        },
        {
          $inc: { balance: -amount },
          $set: { username: user.username }
        },
        { new: true }
      );

      if (!wallet) {
        const currentWallet = await PracticeWallet.findOne({ userId: user._id }).lean();
        return res.status(400).json({
          success: false,
          message: `Insufficient Practice PTS. Current Practice Wallet: ${Number(currentWallet?.balance || 0).toFixed(2)} PTS`
        });
      }
    } else {
      wallet = await PracticeWallet.findOneAndUpdate(
        { userId: user._id },
        {
          $inc: { balance: amount },
          $set: { username: user.username }
        },
        { new: true }
      );
    }

    if (!wallet) {
      return res.status(500).json({
        success: false,
        message: "Practice Wallet could not be updated."
      });
    }

    const referenceId = new mongoose.Types.ObjectId().toString();

    // Audit/notification are best-effort. A successful wallet update must not
    // be turned into a false "failed" toast just because an auxiliary log fails.
    try {
      await writeAudit(
        req,
        `PRACTICE_PTS_${action.toUpperCase()}`,
        user,
        referenceId,
        {
          amount: Number(amount),
          practiceOnly: true,
          balanceAfter: Number(wallet.balance || 0)
        }
      );
    } catch (auditErr) {
      console.warn("PRACTICE ADMIN AUDIT WARNING:", auditErr?.message || auditErr);
    }

    try {
      await notifyPracticeUser(user._id);
    } catch (notifyErr) {
      console.warn("PRACTICE ADMIN NOTIFY WARNING:", notifyErr?.message || notifyErr);
    }

    return res.json({
      success: true,
      message:
        action === "add"
          ? "Practice PTS added."
          : "Practice PTS deducted.",
      username: user.username,
      practiceBalance: Number(wallet.balance || 0)
    });
  } catch (error) {
    console.error("ADMIN PRACTICE TRANSFER ERROR:", error);
    return res.status(500).json({
      success: false,
      message: "Practice PTS update failed."
    });
  }
});


/* =========================
   ADMIN BOOTSTRAP
========================= */

async function ensureAdmin() {
  const username = cleanUsername(process.env.ADMIN_USERNAME);
  const password = String(process.env.ADMIN_PASSWORD || "");
  const email = cleanEmail(process.env.ADMIN_EMAIL);

  if (!username || !password || !email) {
    console.warn("ADMIN_USERNAME/ADMIN_PASSWORD/ADMIN_EMAIL not configured; existing admin users can still log in.");
    return;
  }

  const existing = await User.findOne({ username });

  if (!existing) {
    const hash = await bcrypt.hash(password, 12);
    await User.create({
      username,
      email,
      password: hash,
      role: "admin",
      isAdmin: true
    });
    console.log("Admin account created from environment variables.");
    return;
  }

  existing.role = "admin";
  existing.isAdmin = true;
  existing.email = email;

  // Keep the Render ADMIN_PASSWORD authoritative, but only re-hash when
  // the configured password is actually different from the stored hash.
  const passwordMatches = await bcrypt.compare(password, existing.password);
  if (!passwordMatches) {
    existing.password = await bcrypt.hash(password, 12);
    console.log("Admin password synchronized from environment variables.");
  }

  await existing.save();
}

// Hide internal stack traces and normalize malformed JSON/CORS failures.
app.use((err, req, res, next) => {
  if (err?.type === "entity.parse.failed") return res.status(400).json({ success:false, message:"Invalid JSON." });
  if (String(err?.message || "").includes("CORS origin denied")) return res.status(403).json({ success:false, message:"Origin not allowed." });
  console.error("UNHANDLED REQUEST ERROR:", err?.message || err);
  return res.status(500).json({ success:false, message:"Request failed." });
});

/* =========================
   START
========================= */

async function startServer() {
  try {
    if (!process.env.MONGODB_URI) throw new Error("MONGODB_URI is missing in Render Environment.");
    // DB_NAME keeps cloned deployments isolated even when the same MongoDB
    // cluster connection string is reused.
    await mongoose.connect(process.env.MONGODB_URI, {
      dbName: String(process.env.DB_NAME || "rahul_play")
    });
    console.log("MongoDB connected successfully.");

    await ensureAdmin();
    await getResults();

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`KF8 Backend running on port ${PORT}`);
    });
  } catch (error) {
    console.error("STARTUP ERROR:", error.message);
    process.exit(1);
  }
}

startServer();
