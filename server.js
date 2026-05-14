const express = require("express");
const cors = require("cors");
const { v4: uuidv4 } = require("uuid");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || "plugit-secret-2025";
const SERVICE_FEE = 300; // flat PlugIt service fee per request (naira)
const SHOPPER_CUT = 200; // shopper earns this from the service fee
const PLATFORM_CUT = 100; // platform keeps this

// ── Multer (item image uploads) ───────────────────────────────────────────────
const uploadDir = path.join(__dirname, "public", "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, uploadDir),
  filename: (_, file, cb) => cb(null, Date.now() + "-" + file.originalname.replace(/\s+/g, "_")),
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ── In-memory stores ──────────────────────────────────────────────────────────
let users = [];
let requests = []; // student shopping requests
let vendors = [...seedVendors()]; // external vendors

function seedVendors() {
  return [
    {
      id: "ext1",
      name: "Unity Stationery Hub",
      category: "Stationery",
      icon: "icon-books",
      description: "Textbooks, notebooks, pens, A4 paper, staplers, calculators",
      location: "Sabo, Yaba — Near UNILAG Main Gate",
      contact: "08012345001",
      openHours: "8:00 AM – 5:00 PM",
      tags: ["stationery", "books", "printing"],
    },
    {
      id: "ext2",
      name: "Yaba Fresh Market",
      category: "Groceries",
      icon: "icon-groceries",
      description: "Provisions, toiletries, household items, fresh foodstuff",
      location: "Yaba Market — Ojuelegba Road, Yaba",
      contact: "08012345002",
      openHours: "7:00 AM – 7:00 PM",
      tags: ["groceries", "provisions", "toiletries"],
    },
    {
      id: "ext3",
      name: "Tech Hub Yaba",
      category: "Electronics",
      icon: "icon-electronics",
      description: "Phone accessories, cables, earphones, power banks, USB drives",
      location: "Yaba Tech Mall — Shomolu Street, Yaba",
      contact: "08012345003",
      openHours: "9:00 AM – 6:00 PM",
      tags: ["electronics", "phone", "accessories", "cables"],
    },
    {
      id: "ext4",
      name: "Style & Grace Fashion",
      category: "Clothing",
      icon: "icon-clothing",
      description: "Casual wear, event outfits, fabrics, alterations services",
      location: "Yaba Fashion District — Oremade Street, Yaba",
      contact: "08012345004",
      openHours: "10:00 AM – 7:00 PM",
      tags: ["clothing", "fashion", "fabric", "event"],
    },
    {
      id: "ext5",
      name: "HealthCare Plus Pharmacy",
      category: "Health",
      icon: "icon-medicine",
      description: "Medications, vitamins, first aid supplies, personal care items",
      location: "Yaba Clinic Area — Sabo Road, Yaba",
      contact: "08012345005",
      openHours: "8:00 AM – 8:00 PM",
      tags: ["health", "pharmacy", "medicine", "first aid"],
    },
    {
      id: "ext6",
      name: "PrintPro Yaba",
      category: "Printing",
      icon: "icon-printer",
      description: "Printing, binding, lamination, scanning, photocopying services",
      location: "University Road, Yaba",
      contact: "08012345006",
      openHours: "7:30 AM – 6:00 PM",
      tags: ["printing", "binding", "scanning", "documents"],
    },
  ];
}

// ── Auth middleware ────────────────────────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Login required" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = users.find(u => u.id === payload.id);
    if (!user) return res.status(401).json({ error: "User not found" });
    req.user = sanitize(user);
    next();
  } catch { res.status(401).json({ error: "Invalid or expired token" }); }
}

function sanitize(u) { const { passwordHash, ...s } = u; return s; }

// ── AUTH ──────────────────────────────────────────────────────────────────────
app.post("/api/auth/register", async (req, res) => {
  const { name, email, password, role, phone, matric } = req.body;
  if (!name || !email || !password || !role) return res.status(400).json({ error: "Missing required fields" });
  if (!["student", "shopper", "vendor"].includes(role)) return res.status(400).json({ error: "Invalid role" });
  if (users.find(u => u.email === email)) return res.status(400).json({ error: "Email already registered" });

  const passwordHash = await bcrypt.hash(password, 10);
  const user = {
    id: uuidv4(), name, email, passwordHash, role,
    phone: phone || "", matric: matric || "",
    rating: role === "shopper" ? { total: 0, count: 0 } : null,
    completedJobs: 0,
    createdAt: new Date().toISOString(),
  };
  users.push(user);
  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "7d" });
  res.status(201).json({ token, user: sanitize(user) });
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) return res.status(401).json({ error: "Invalid email or password" });
  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, user: sanitize(user) });
});

app.get("/api/auth/me", auth, (req, res) => res.json(req.user));

// ── VENDORS (external sources) ─────────────────────────────────────────────────
app.get("/api/vendors", (_, res) => res.json(vendors));

app.post("/api/vendors", auth, (req, res) => {
  if (req.user.role !== "vendor") return res.status(403).json({ error: "Vendor accounts only" });
  const { name, category, icon, description, location, contact, openHours, tags } = req.body;
  if (!name || !category || !description || !location) return res.status(400).json({ error: "Missing fields" });
  const vendor = { id: uuidv4(), name, category, icon: icon || "icon-store", description, location, contact: contact || "", openHours: openHours || "", tags: tags || [], ownerId: req.user.id, createdAt: new Date().toISOString() };
  vendors.push(vendor);
  res.status(201).json(vendor);
});

// ── REQUESTS ──────────────────────────────────────────────────────────────────
// Student posts a new shopping request
app.post("/api/requests", auth, upload.single("image"), (req, res) => {
  if (req.user.role !== "student") return res.status(403).json({ error: "Students only" });
  const { description, itemBudget, deliveryLocation, urgency, suggestedVendorId, notes } = req.body;
  if (!description || !deliveryLocation) return res.status(400).json({ error: "Description and delivery location are required" });

  const request = {
    id: uuidv4(),
    studentId: req.user.id,
    studentName: req.user.name,
    studentPhone: req.user.phone,
    description,
    itemBudget: itemBudget ? Number(itemBudget) : null,
    serviceFee: SERVICE_FEE,
    totalEstimate: itemBudget ? Number(itemBudget) + SERVICE_FEE : null,
    deliveryLocation,
    urgency: urgency || "normal", // normal | urgent
    suggestedVendorId: suggestedVendorId || null,
    notes: notes || "",
    imagePath: req.file ? "/uploads/" + req.file.filename : null,
    status: "open", // open | claimed | sourcing | delivered | cancelled | disputed
    shopperId: null,
    shopperName: null,
    shopperPhone: null,
    negotiation: [], // array of { from, message, proposedFee, timestamp }
    finalItemCost: null,
    finalServiceFee: SERVICE_FEE,
    shopperEarning: SHOPPER_CUT,
    platformEarning: PLATFORM_CUT,
    rating: null,
    createdAt: new Date().toISOString(),
    updatedAt: null,
  };

  requests.push(request);
  res.status(201).json(request);
});

// Get requests — filtered by role
app.get("/api/requests", auth, (req, res) => {
  const { status } = req.query;
  let result = [...requests].reverse();

  if (req.user.role === "student") {
    result = result.filter(r => r.studentId === req.user.id);
  } else if (req.user.role === "shopper") {
    // Shoppers see open requests + their own claimed ones
    result = result.filter(r => r.status === "open" || r.shopperId === req.user.id);
  }
  // vendors see all (read-only, for market context)

  if (status) result = result.filter(r => r.status === status);
  res.json(result);
});

// Get single request
app.get("/api/requests/:id", auth, (req, res) => {
  const r = requests.find(r => r.id === req.params.id);
  if (!r) return res.status(404).json({ error: "Not found" });
  res.json(r);
});

// Shopper claims a request
app.patch("/api/requests/:id/claim", auth, (req, res) => {
  if (req.user.role !== "shopper") return res.status(403).json({ error: "Shoppers only" });
  const r = requests.find(r => r.id === req.params.id);
  if (!r) return res.status(404).json({ error: "Not found" });
  if (r.status !== "open") return res.status(400).json({ error: "Request already claimed" });

  r.shopperId = req.user.id;
  r.shopperName = req.user.name;
  r.shopperPhone = req.user.phone;
  r.status = "claimed";
  r.updatedAt = new Date().toISOString();
  res.json(r);
});

// Negotiation message (student or shopper)
app.post("/api/requests/:id/negotiate", auth, (req, res) => {
  const r = requests.find(r => r.id === req.params.id);
  if (!r) return res.status(404).json({ error: "Not found" });
  if (!["student", "shopper"].includes(req.user.role)) return res.status(403).json({ error: "Forbidden" });
  if (r.status === "open" || r.status === "delivered" || r.status === "cancelled") return res.status(400).json({ error: "Cannot negotiate at this stage" });

  const { message, proposedFee } = req.body;
  if (!message) return res.status(400).json({ error: "Message required" });

  r.negotiation.push({
    from: req.user.role,
    name: req.user.name,
    message,
    proposedFee: proposedFee ? Number(proposedFee) : null,
    timestamp: new Date().toISOString(),
  });

  // If shopper proposes a new fee, update pending
  if (proposedFee && req.user.role === "shopper") {
    r.pendingFeeProposal = Number(proposedFee);
  }

  r.updatedAt = new Date().toISOString();
  res.json(r);
});

// Student accepts a proposed fee
app.patch("/api/requests/:id/accept-fee", auth, (req, res) => {
  if (req.user.role !== "student") return res.status(403).json({ error: "Students only" });
  const r = requests.find(r => r.id === req.params.id);
  if (!r) return res.status(404).json({ error: "Not found" });
  if (!r.pendingFeeProposal) return res.status(400).json({ error: "No pending proposal" });

  r.finalServiceFee = r.pendingFeeProposal;
  r.shopperEarning = Math.round(r.pendingFeeProposal * 0.67);
  r.platformEarning = r.pendingFeeProposal - r.shopperEarning;
  r.pendingFeeProposal = null;
  r.updatedAt = new Date().toISOString();
  res.json(r);
});

// Update status (shopper or student)
app.patch("/api/requests/:id/status", auth, (req, res) => {
  const { status, finalItemCost } = req.body;
  const r = requests.find(r => r.id === req.params.id);
  if (!r) return res.status(404).json({ error: "Not found" });

  const validTransitions = {
    shopper: { claimed: ["sourcing"], sourcing: ["delivered"] },
    student: { claimed: ["cancelled"], sourcing: ["cancelled", "disputed"], delivered: ["disputed"] },
  };

  const allowed = validTransitions[req.user.role]?.[r.status] || [];
  if (!allowed.includes(status)) return res.status(400).json({ error: `Cannot move from ${r.status} to ${status}` });

  r.status = status;
  if (finalItemCost) r.finalItemCost = Number(finalItemCost);
  r.updatedAt = new Date().toISOString();

  // Update shopper stats on delivery
  if (status === "delivered") {
    const shopper = users.find(u => u.id === r.shopperId);
    if (shopper) shopper.completedJobs = (shopper.completedJobs || 0) + 1;
  }

  res.json(r);
});

// Student rates a completed request
app.post("/api/requests/:id/rate", auth, (req, res) => {
  if (req.user.role !== "student") return res.status(403).json({ error: "Students only" });
  const r = requests.find(r => r.id === req.params.id);
  if (!r) return res.status(404).json({ error: "Not found" });
  if (r.studentId !== req.user.id) return res.status(403).json({ error: "Forbidden" });
  if (r.status !== "delivered") return res.status(400).json({ error: "Can only rate delivered requests" });
  if (r.rating) return res.status(400).json({ error: "Already rated" });

  const { score, comment } = req.body;
  if (!score || score < 1 || score > 5) return res.status(400).json({ error: "Score must be 1–5" });

  r.rating = { score: Number(score), comment: comment || "", timestamp: new Date().toISOString() };
  r.updatedAt = new Date().toISOString();

  const shopper = users.find(u => u.id === r.shopperId);
  if (shopper?.rating) {
    shopper.rating.total += Number(score);
    shopper.rating.count += 1;
  }

  res.json(r);
});

// ── LEADERBOARD ───────────────────────────────────────────────────────────────
app.get("/api/shoppers/leaderboard", (_, res) => {
  const shoppers = users
    .filter(u => u.role === "shopper")
    .map(u => ({
      id: u.id,
      name: u.name,
      completedJobs: u.completedJobs || 0,
      avgRating: u.rating?.count ? (u.rating.total / u.rating.count).toFixed(1) : null,
      ratingCount: u.rating?.count || 0,
    }))
    .sort((a, b) => b.completedJobs - a.completedJobs || (b.avgRating || 0) - (a.avgRating || 0));
  res.json(shoppers);
});

// ── SERVE FRONTEND ────────────────────────────────────────────────────────────
app.get("*", (_, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`PlugIt running on http://localhost:${PORT}`));
