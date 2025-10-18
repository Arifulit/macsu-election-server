// ✅ server.js
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

// ==============================
// 🔧 Configuration
// ==============================
const app = express();
const port = process.env.PORT || 4000;
const MONGO_URI = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.1bdxs.mongodb.net/online-voting?retryWrites=true&w=majority`;
const JWT_SECRET = process.env.JWT_SECRET || "change_this_secret";
const REFRESH_SECRET = process.env.REFRESH_SECRET || (JWT_SECRET + "_refresh");
// ==============================
// 🧩 Middleware
// ==============================
app.use(cors());
app.use(express.json());

// ==============================
// 🌍 MongoDB Connection
// ==============================
mongoose
  .connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

// ==============================
// 👥 Schemas and Models
// ==============================

// User Schema
const UserSchema = new mongoose.Schema(
  {
    email: { type: String, unique: true },
    passwordHash: String,
    fullName: String,
    role: { type: String, enum: ["voter", "admin", "candidate"], default: "voter" },
    isVerified: { type: Boolean, default: false },
    verificationCode: String,
    refreshTokens: { type: [String], default: [] },
  },
  { timestamps: true }
);

const User = mongoose.model("User", UserSchema);

// Voter Schema
const VoterSchema = new mongoose.Schema({
  name: String,
  nid: String,
  address: String,
  // keep list of voted candidate ids (legacy) and per-position votes
  votedCandidates: { type: [{ type: mongoose.Schema.Types.ObjectId, ref: "Candidate" }], default: [] },
  // per-position votes: array of { position, candidate }
  voted: [
    {
      position: { type: String },
      candidate: { type: mongoose.Schema.Types.ObjectId, ref: "Candidate" },
    },
  ],
});

const Voter = mongoose.model("Voter", VoterSchema);

// Candidate Schema
const CandidateSchema = new mongoose.Schema({
  position: { type: String, default: "" },
  name: String,
  studentId: String,
  department: String,
  photoUrl: String,
  displayOrder: { type: Number, default: 0 },
  manifesto: String,
  party: String,
  symbol: String,
  votes: { type: Number, default: 0 },
});

const Candidate = mongoose.model("Candidate", CandidateSchema);

const ElectionConfigSchema = new mongoose.Schema(
  {
    electionTitle: { type: String, required: true },
    description: String,
    startDate: Date,
    endDate: Date,
    votingMethod: { type: String, default: "online" },
    maxVotesPerVoter: { type: Number, default: 1 },
    allowMultiplePositions: { type: Boolean, default: false },
    resultVisibility: { type: String, enum: ["public", "after_closure", "admin_only"], default: "after_closure" },
    createdBy: String,
    isActive: { type: Boolean, default: false },
    settings: mongoose.Schema.Types.Mixed,
  },
  { timestamps: true }
);

const ElectionConfig = mongoose.model("ElectionConfig", ElectionConfigSchema);

// ==============================
// 🔐 Auth Middleware
// ==============================
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: "No token provided" });

  const token = auth.split(" ")[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.id;
    req.userRole = payload.role;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// ==============================
// 🧠 Helper Functions
// ==============================
function generateCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ==============================
// 🔑 AUTH ROUTES
// ==============================


// Register
// ...existing code...
app.post("/api/auth/register", async (req, res) => {
  try {
    const { email, password, fullName, role } = req.body;
    if (!email || !password) return res.status(400).json({ ok: false, error: "Missing fields" });

    const exists = await User.findOne({ email });
    if (exists) return res.status(400).json({ ok: false, error: "Email already registered" });

    const passwordHash = await bcrypt.hash(password, 10);

    const allowedRoles = ["admin", "voter", "candidate"];
    const roleValue = allowedRoles.includes(role) ? role : "voter";

    const user = new User({
      email,
      passwordHash,
      fullName,
      // disable verification: mark as verified immediately and do not store verificationCode
      isVerified: true,
      role: roleValue,
    });
    await user.save();

    // If registering as a candidate, create a Candidate record (optional fields from body)
    if (roleValue === "candidate") {
      const cand = new Candidate({
        name: fullName || "",
        party: req.body.party || "",
        symbol: req.body.symbol || "",
      });
      await cand.save();
    }

    // create tokens
    const accessToken = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: "15m" }
    );
    const refreshToken = jwt.sign(
      { id: user._id },
      REFRESH_SECRET,
      { expiresIn: "30d" }
    );
    user.refreshTokens.push(refreshToken);
    await user.save();

    return res.status(201).json({
      ok: true,
      message: "Registration successful.",
      data: {
        user: {
          id: user._id,
          email: user.email,
          fullName: user.fullName,
          role: user.role,
          isVerified: user.isVerified,
        },
        accessToken,
        refreshToken,
      },
    });
  } 
  catch (err) {
    console.error("Register error:", err);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ ok: false, error: "Missing fields" });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ ok: false, error: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(400).json({ ok: false, error: "Invalid credentials" });

    const accessToken = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: "15m" }
    );

    const refreshToken = jwt.sign(
      { id: user._id },
      REFRESH_SECRET,
      { expiresIn: "30d" }
    );

    // store refresh token
    user.refreshTokens.push(refreshToken);
    await user.save();

    return res.json({
      ok: true,
      message: "Login successful",
      data: {
        user: {
          id: user._id,
          email: user.email,
          fullName: user.fullName,
          role: user.role,
          isVerified: user.isVerified,
        },
        accessToken,
        refreshToken,
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// Refresh access token
app.post("/api/auth/refresh", async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(401).json({ error: "No refresh token" });

  try {
    const payload = jwt.verify(refreshToken, REFRESH_SECRET);
    const user = await User.findById(payload.id);
    if (!user || !user.refreshTokens.includes(refreshToken))
      return res.status(403).json({ error: "Invalid refresh token" });

    const accessToken = jwt.sign(
      { id: user._id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: "15m" }
    );

    return res.json({ accessToken });
  } catch (err) {
    return res.status(403).json({ error: "Invalid refresh token" });
  }
});

// Logout (invalidate refresh token)
// ...existing code...
// Optional helper: allow logout via GET for quick testing (not recommended for production)
app.get("/api/auth/logout", async (req, res) => {
  // accept refreshToken as query ?refreshToken=... or as Authorization: Bearer <token>
  const refreshToken =
    req.query.refreshToken ||
    (req.headers.authorization ? req.headers.authorization.split(" ")[1] : null);

  if (!refreshToken) return res.json({ ok: true });

  try {
    const payload = jwt.verify(refreshToken, REFRESH_SECRET);
    const user = await User.findById(payload.id);
    if (user) {
      user.refreshTokens = user.refreshTokens.filter((t) => t !== refreshToken);
      await user.save();
    }
  } catch (err) {
    // ignore invalid token
  }

  return res.json({ ok: true, message: "Logout successful" });
});
// ...existing code...


// Verify Code
app.post("/api/auth/verify", async (req, res) => {
  const { email, code } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: "User not found" });

  if (user.verificationCode === code) {
    user.isVerified = true;
    user.verificationCode = null;
    await user.save();
    return res.json({ ok: true, message: "Verification successful" });
  }
  return res.status(400).json({ error: "Invalid verification code" });
});

// Get current user
app.get("/api/auth/me", authMiddleware, async (req, res) => {
  const user = await User.findById(req.userId).select(
    "-passwordHash -verificationCode"
  );
  if (!user) return res.status(404).json({ error: "User not found" });
  return res.json({
    user: {
      email: user.email,
      fullName: user.fullName,
      is_verified: user.isVerified,
    },
  });
});

// ==============================
// 🗳 Voting System Routes
// ==============================

// Get all candidates
app.get("/api/candidates", async (req, res) => {
  const candidates = await Candidate.find();
  res.json(candidates);
});







// Replace /api/votes handler with position-aware logic
app.post("/api/votes", authMiddleware, async (req, res) => {
  try {
    let { candidateId } = req.body;
    if (!candidateId) return res.status(400).json({ error: "Missing candidateId" });

    // accept single id or array of ids
    const candidateIds = Array.isArray(candidateId) ? candidateId : [candidateId];

    // load or create voter (use same _id as User)
    let voter = await Voter.findById(req.userId);
    if (!voter) {
      const user = await User.findById(req.userId).select("fullName email");
      voter = new Voter({
        _id: req.userId,
        name: user?.fullName || user?.email || "",
        votedCandidates: [],
        voted: [],
      });
    }

    // fetch election config to determine max votes per voter (total)
    const config = await ElectionConfig.findOne();
      const maxVotes = (config && config.maxVotesPerVoter) ? config.maxVotesPerVoter : Infinity; // if not set, allow any positions

    // Build current voted positions set
    const votedPositions = new Set((voter.voted || []).map((v) => v.position));

    // Validate candidate ids, gather positions
    const candidates = await Candidate.find({ _id: { $in: candidateIds } });
    if (candidates.length !== candidateIds.length) {
      return res.status(404).json({ error: "One or more candidates not found" });
    }

    // check for attempting to vote multiple candidates for same position in this request
    const positionsInRequest = {};
    for (const c of candidates) {
      const pos = c.position || ""; // treat empty as position-less
      if (positionsInRequest[pos]) {
        return res.status(400).json({ error: `Multiple candidates for same position in request: ${pos}` });
      }
      positionsInRequest[pos] = true;
    }

    // check per-position already voted and total max votes
    const newPositions = candidates.map((c) => c.position || "");
    // if any position already voted by this voter -> error
    for (const pos of newPositions) {
      if (votedPositions.has(pos)) {
        return res.status(400).json({ error: `You have already voted for position: ${pos}` });
      }
    }

    // enforce total votes limit if configured (count existing + new)
 if (!config?.allowMultiplePositions) {
      const totalAfter = (voter.voted.length || 0) + newPositions.length;
      if (Number.isFinite(maxVotes) && totalAfter > maxVotes) {
        return res.status(400).json({ error: `Vote limit exceeded. Max votes allowed: ${maxVotes}` });
      }
    }

    // apply votes: increment candidate.votes and record voter's per-position vote
    for (const c of candidates) {
      c.votes = (c.votes || 0) + 1;
      await c.save();

      voter.votedCandidates.push(c._id); // legacy list
      voter.voted.push({ position: c.position || "", candidate: c._id });
    }

    await voter.save();

    return res.json({
      message: "Vote cast successfully",
      voted: voter.voted,
    });
  } catch (err) {
    console.error("Vote error:", err);
    return res.status(500).json({ error: "Server error" });
  }
});
// ...existing code...


app.post("/api/election-config", authMiddleware, async (req, res) => {
  try {
    const data = req.body;
    // Upsert single config document
    const config = await ElectionConfig.findOneAndUpdate(
      {},
      { $set: data },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );
    return res.json({ ok: true, config });
  } catch (err) {
    console.error("Error saving election config:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/election-config", async (req, res) => {
  try {
    const config = await ElectionConfig.findOne().sort({ updatedAt: -1 });
    if (!config) return res.status(404).json({ error: "No config found" });
    return res.json(config);
  } catch (err) {
    console.error("Error fetching election config:", err);
    return res.status(500).json({ error: "Server error" });
  }
});


// Add new candidate
// ...existing code...


// Add new candidate (admin only)


// Add new candidate (admin only)
app.post("/api/candidates", authMiddleware, async (req, res) => {
  try {
    // require admin role to add candidates
    if (req.userRole !== "admin")
      return res.status(403).json({ ok: false, error: "Forbidden: admin only" });

    const {
      position,
      name,
      studentId,
      department,
      photoUrl,
      displayOrder,
      manifesto,
      party,
      symbol,
    } = req.body;

    const newCandidate = new Candidate({
      position,
      name,
      studentId,
      department,
      photoUrl,
      displayOrder,
      manifesto,
      party,
      symbol,
    });

    await newCandidate.save();

    return res.status(201).json({
      message: "Candidate added successfully",
      newCandidate,
    });
  } catch (err) {
    console.error("Error adding candidate:", err);
    return res.status(500).json({ error: "Server error" });
  }
});

// Results route
app.get("/api/results", async (req, res) => {
  try {
    const candidates = await Candidate.find().sort({ votes: -1 });
    const totalVotes = candidates.reduce((sum, c) => sum + (c.votes || 0), 0);
    return res.json({ totalVotes, candidates });
  } catch (err) {
    console.error("Error fetching results:", err);
    return res.status(500).json({ error: "Server error" });
  }
});
// Cast a vote
app.post("/api/vote/:id", authMiddleware, async (req, res) => {
  const { id } = req.params;
  const voter = await Voter.findOne({ _id: req.userId });
  if (voter && voter.voted)
    return res.status(400).json({ error: "You have already voted" });

  const candidate = await Candidate.findById(id);
  if (!candidate) return res.status(404).json({ error: "Candidate not found" });

  candidate.votes += 1;
  await candidate.save();

  if (voter) {
    voter.voted = true;
    await voter.save();
  }

  res.json({ message: "Vote cast successfully" });
});

// ==============================
// 🏠 Root Route
// ==============================
app.get("/", (req, res) => {
  res.send("🗳 Online Voting Server is Running!");
});

// ==============================
// 🚀 Start Server
// ==============================
app.listen(port, () => {
  console.log(`✅ Server running on port ${port}`);
});
