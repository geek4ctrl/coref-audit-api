import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import { query } from "./db.js";
import "dotenv/config";

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "";
const TOKEN_EXPIRY = "8h";

const ROLES = [
  "ADMIN",
  "CHEF_SG",
  "ASSISTANT_CHEF",
  "RECEPTION",
  "SECRETARIAT",
  "PILIER",
  "PILIER_COORD",
  "SERVICE_INTERNE",
  "AUDITEUR"
];

const ensureJwtSecret = () => {
  if (!JWT_SECRET) {
    throw new Error("JWT_SECRET is missing. Set it in .env before running the API.");
  }
};

const generateToken = (user) => {
  ensureJwtSecret();
  return jwt.sign(
    { userId: user.id, role: user.role },
    JWT_SECRET,
    { expiresIn: TOKEN_EXPIRY }
  );
};

const authRequired = (req, res, next) => {
  const authHeader = req.headers.authorization || "";
  const [scheme, token] = authHeader.split(" ");

  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({ error: "Missing or invalid Authorization header" });
  }

  try {
    ensureJwtSecret();
    req.user = jwt.verify(token, JWT_SECRET);
    return next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
};

const requireRole = (roles) => (req, res, next) => {
  if (!req.user || !roles.includes(req.user.role)) {
    return res.status(403).json({ error: "Forbidden" });
  }
  return next();
};

const sanitizeUser = (user) => ({
  id: user.id,
  name: user.name,
  email: user.email,
  role: user.role,
  serviceId: user.service_id,
  isActive: user.is_active,
  createdAt: user.created_at,
  updatedAt: user.updated_at
});

const sanitizeReceptionDocument = (document) => ({
  id: document.id,
  number: document.number,
  documentType: document.document_type,
  receivedDate: document.received_date,
  sender: document.sender,
  subject: document.subject,
  category: document.category,
  confidentiality: document.confidentiality,
  observations: document.observations,
  status: document.status,
  createdByUserId: document.created_by_user_id,
  createdAt: document.created_at
});

const sanitizeDistributionDocument = (document) => ({
  id: document.id,
  number: document.number,
  subject: document.subject,
  status: document.status,
  createdAt: document.created_at,
  deliveredAt: document.delivered_at,
  hasBordereau: Boolean(document.bordereau_id),
  bordereauNumber: document.bordereau_number || null
});

const sanitizeBordereau = (bordereau) => ({
  id: bordereau.id,
  number: bordereau.number,
  status: bordereau.status === "Non signÃ©" ? "Non signé" : bordereau.status,
  generatedAt: bordereau.generated_at,
  signedAt: bordereau.signed_at,
  document: {
    id: bordereau.document_id,
    number: bordereau.document_number,
    subject: bordereau.document_subject
  }
});

app.get("/", (req, res) => {
  res.send("API is running");
});

app.get("/health/db", async (req, res) => {
  const result = await query("SELECT NOW() as now");
  res.json(result.rows[0]);
});

app.post("/auth/register", async (req, res) => {
  try {
    const { name, email, password, role, serviceId } = req.body || {};

    if (!name || !email || !password || !role) {
      return res.status(400).json({ error: "name, email, password, and role are required" });
    }

    if (!ROLES.includes(role)) {
      return res.status(400).json({ error: "Invalid role" });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const result = await query(
      `
      INSERT INTO users (name, email, password_hash, role, service_id)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *
      `,
      [name, email.toLowerCase(), passwordHash, role, serviceId || null]
    );

    const user = result.rows[0];
    return res.status(201).json({ user: sanitizeUser(user) });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ error: "Email already exists" });
    }
    return res.status(500).json({
      error: "Failed to register user",
      detail: error.message,
      code: error.code
    });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};

    if (!email || !password) {
      return res.status(400).json({ error: "email and password are required" });
    }

    const result = await query("SELECT * FROM users WHERE email = $1", [email.toLowerCase()]);
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const matches = await bcrypt.compare(password, user.password_hash);
    if (!matches) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = generateToken(user);
    return res.json({ token, user: sanitizeUser(user) });
  } catch (error) {
    return res.status(500).json({ error: "Failed to login" });
  }
});

app.get("/users", authRequired, requireRole(["ADMIN"]), async (req, res) => {
  try {
    const result = await query("SELECT * FROM users ORDER BY created_at DESC");
    return res.json({ users: result.rows.map(sanitizeUser) });
  } catch (error) {
    return res.status(500).json({ error: "Failed to fetch users" });
  }
});

app.get("/users/:id", authRequired, requireRole(["ADMIN"]), async (req, res) => {
  try {
    const result = await query("SELECT * FROM users WHERE id = $1", [req.params.id]);
    const user = result.rows[0];
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    return res.json({ user: sanitizeUser(user) });
  } catch (error) {
    return res.status(500).json({ error: "Failed to fetch user" });
  }
});

app.post("/users", authRequired, requireRole(["ADMIN"]), async (req, res) => {
  try {
    const { name, email, password, role, serviceId, isActive } = req.body || {};
    if (!name || !email || !password || !role) {
      return res.status(400).json({ error: "name, email, password, and role are required" });
    }

    if (!ROLES.includes(role)) {
      return res.status(400).json({ error: "Invalid role" });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const result = await query(
      `
      INSERT INTO users (name, email, password_hash, role, service_id, is_active)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *
      `,
      [name, email.toLowerCase(), passwordHash, role, serviceId || null, isActive !== false]
    );

    return res.status(201).json({ user: sanitizeUser(result.rows[0]) });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ error: "Email already exists" });
    }
    return res.status(500).json({ error: "Failed to create user" });
  }
});

app.patch("/users/:id", authRequired, requireRole(["ADMIN"]), async (req, res) => {
  try {
    const { name, email, password, role, serviceId, isActive } = req.body || {};

    if (role && !ROLES.includes(role)) {
      return res.status(400).json({ error: "Invalid role" });
    }

    const existing = await query("SELECT * FROM users WHERE id = $1", [req.params.id]);
    const user = existing.rows[0];
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const passwordHash = password ? await bcrypt.hash(password, 12) : user.password_hash;
    const updated = await query(
      `
      UPDATE users
      SET name = $1,
          email = $2,
          password_hash = $3,
          role = $4,
          service_id = $5,
          is_active = $6
      WHERE id = $7
      RETURNING *
      `,
      [
        name ?? user.name,
        (email ?? user.email).toLowerCase(),
        passwordHash,
        role ?? user.role,
        serviceId ?? user.service_id,
        isActive ?? user.is_active,
        req.params.id
      ]
    );

    return res.json({ user: sanitizeUser(updated.rows[0]) });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ error: "Email already exists" });
    }
    return res.status(500).json({ error: "Failed to update user" });
  }
});

app.delete("/users/:id", authRequired, requireRole(["ADMIN"]), async (req, res) => {
  try {
    const result = await query("DELETE FROM users WHERE id = $1 RETURNING id", [req.params.id]);
    if (!result.rows[0]) {
      return res.status(404).json({ error: "User not found" });
    }
    return res.status(204).send();
  } catch (error) {
    return res.status(500).json({ error: "Failed to delete user" });
  }
});

app.get("/reception/documents/recent", authRequired, requireRole(["ADMIN", "RECEPTION"]), async (req, res) => {
  try {
    const limit = Math.min(Number.parseInt(req.query.limit, 10) || 10, 50);
    const [result, totalResult] = await Promise.all([
      query(
      `
      SELECT *
      FROM reception_documents
      ORDER BY created_at DESC
      LIMIT $1
      `,
      [limit]
      ),
      query(`SELECT COUNT(*)::INT AS total_count FROM reception_documents`)
    ]);

    return res.json({
      totalCount: totalResult.rows[0]?.total_count ?? 0,
      documents: result.rows.map(sanitizeReceptionDocument)
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to fetch reception documents" });
  }
});

app.get("/reception/dashboard/stats", authRequired, requireRole(["ADMIN", "RECEPTION"]), async (req, res) => {
  try {
    const [entriesTodayResult, toDistributeResult, toScanResult, pendingBordereauxResult, distributedThisMonthResult] = await Promise.all([
      query(
        `
        SELECT COUNT(*)::INT AS value
        FROM reception_documents
        WHERE created_at::date = CURRENT_DATE
        `
      ),
      query(
        `
        SELECT COUNT(*)::INT AS value
        FROM reception_documents
        WHERE status <> 'Remis'
        `
      ),
      query(
        `
        SELECT COUNT(*)::INT AS value
        FROM reception_documents d
        LEFT JOIN reception_bordereaux b ON b.document_id = d.id
        WHERE b.id IS NULL
        `
      ),
      query(
        `
        SELECT COUNT(*)::INT AS value
        FROM reception_bordereaux
        WHERE status <> 'Signé'
        `
      ),
      query(
        `
        SELECT COUNT(*)::INT AS value
        FROM reception_documents
        WHERE status = 'Remis'
          AND delivered_at >= date_trunc('month', CURRENT_DATE)
          AND delivered_at < (date_trunc('month', CURRENT_DATE) + INTERVAL '1 month')
        `
      )
    ]);

    return res.json({
      entriesToday: entriesTodayResult.rows[0]?.value ?? 0,
      toScan: toScanResult.rows[0]?.value ?? 0,
      toDistribute: toDistributeResult.rows[0]?.value ?? 0,
      pendingBordereaux: pendingBordereauxResult.rows[0]?.value ?? 0,
      distributedThisMonth: distributedThisMonthResult.rows[0]?.value ?? 0
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to fetch reception dashboard stats" });
  }
});

app.get("/reception/search", authRequired, requireRole(["ADMIN", "RECEPTION"]), async (req, res) => {
  try {
    const rawQuery = typeof req.query.q === "string" ? req.query.q.trim() : "";
    const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 30, 1), 100);

    if (!rawQuery) {
      return res.json({ results: [] });
    }

    const likeQuery = `%${rawQuery}%`;
    const result = await query(
      `
      SELECT
        d.id,
        d.number,
        d.subject,
        d.status,
        d.sender,
        d.category,
        d.created_at,
        d.delivered_at
      FROM reception_documents d
      WHERE d.number ILIKE $1
         OR d.subject ILIKE $1
         OR d.sender ILIKE $1
         OR d.category ILIKE $1
         OR d.confidentiality ILIKE $1
         OR d.status ILIKE $1
      ORDER BY d.created_at DESC
      LIMIT $2
      `,
      [likeQuery, limit]
    );

    const results = result.rows.map((row) => ({
      id: row.id,
      number: row.number,
      subject: row.subject,
      status: row.status,
      sender: row.sender,
      category: row.category,
      createdAt: row.created_at,
      deliveredAt: row.delivered_at
    }));

    return res.json({ results });
  } catch (error) {
    return res.status(500).json({ error: "Failed to search reception documents" });
  }
});

app.post("/reception/documents", authRequired, requireRole(["ADMIN", "RECEPTION"]), async (req, res) => {
  try {
    const {
      documentType,
      receivedDate,
      sender,
      subject,
      category,
      confidentiality,
      observations
    } = req.body || {};

    if (!documentType || !receivedDate || !sender || !subject || !category || !confidentiality) {
      return res.status(400).json({
        error: "documentType, receivedDate, sender, subject, category, and confidentiality are required"
      });
    }

    const year = new Date(receivedDate).getFullYear();
    if (!Number.isInteger(year) || year < 2000) {
      return res.status(400).json({ error: "Invalid receivedDate" });
    }

    const sequenceResult = await query(
      `
      SELECT COALESCE(MAX(SUBSTRING(number FROM 12)::INT), 0) + 1 AS next_seq
      FROM reception_documents
      WHERE number LIKE $1
      `,
      [`COREF-${year}-%`]
    );

    const nextSequence = String(sequenceResult.rows[0].next_seq).padStart(4, "0");
    const number = `COREF-${year}-${nextSequence}`;

    const result = await query(
      `
      INSERT INTO reception_documents (
        number,
        document_type,
        received_date,
        sender,
        subject,
        category,
        confidentiality,
        observations,
        created_by_user_id
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
      RETURNING *
      `,
      [
        number,
        documentType,
        receivedDate,
        sender,
        subject,
        category,
        confidentiality,
        observations || null,
        req.user.userId
      ]
    );

    return res.status(201).json({ document: sanitizeReceptionDocument(result.rows[0]) });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ error: "A document number conflict occurred. Please retry." });
    }
    return res.status(500).json({ error: "Failed to create reception document" });
  }
});

app.get("/reception/distributions/overview", authRequired, requireRole(["ADMIN", "RECEPTION"]), async (req, res) => {
  try {
    const [toDistributeResult, distributedTodayResult] = await Promise.all([
      query(
      `
      SELECT d.*, b.id AS bordereau_id, b.number AS bordereau_number
      FROM reception_documents d
      LEFT JOIN reception_bordereaux b ON b.document_id = d.id
      WHERE d.status <> 'Remis'
      ORDER BY d.created_at DESC
      `
      ),
      query(
      `
      SELECT d.*, b.id AS bordereau_id, b.number AS bordereau_number
      FROM reception_documents d
      LEFT JOIN reception_bordereaux b ON b.document_id = d.id
      WHERE d.status = 'Remis'
        AND d.delivered_at::date = CURRENT_DATE
      ORDER BY d.delivered_at DESC, d.created_at DESC
      `
      )
    ]);

    return res.json({
      toDistributeCount: toDistributeResult.rows.length,
      distributedTodayCount: distributedTodayResult.rows.length,
      toDistribute: toDistributeResult.rows.map(sanitizeDistributionDocument),
      distributedToday: distributedTodayResult.rows.map(sanitizeDistributionDocument)
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to fetch distributions overview" });
  }
});

app.post("/reception/distributions/:id/mark-delivered", authRequired, requireRole(["ADMIN", "RECEPTION"]), async (req, res) => {
  try {
    const result = await query(
      `
      UPDATE reception_documents
      SET status = 'Remis',
          delivered_at = NOW()
      WHERE id = $1
      RETURNING *
      `,
      [req.params.id]
    );

    const document = result.rows[0];
    if (!document) {
      return res.status(404).json({ error: "Document not found" });
    }

    return res.json({ document: sanitizeReceptionDocument(document) });
  } catch (error) {
    return res.status(500).json({ error: "Failed to mark document as delivered" });
  }
});

app.post("/reception/distributions/:id/generate-bordereau", authRequired, requireRole(["ADMIN", "RECEPTION"]), async (req, res) => {
  try {
    const documentResult = await query("SELECT * FROM reception_documents WHERE id = $1", [req.params.id]);
    const document = documentResult.rows[0];

    if (!document) {
      return res.status(404).json({ error: "Document not found" });
    }

    const existingResult = await query(
      "SELECT * FROM reception_bordereaux WHERE document_id = $1",
      [req.params.id]
    );

    if (existingResult.rows[0]) {
      return res.json({ bordereau: existingResult.rows[0], alreadyExists: true });
    }

    const year = new Date().getFullYear();
    const sequenceResult = await query(
      `
      SELECT COALESCE(MAX(SUBSTRING(number FROM 10)::INT), 0) + 1 AS next_seq
      FROM reception_bordereaux
      WHERE number LIKE $1
      `,
      [`BORD-${year}-%`]
    );

    const nextSequence = String(sequenceResult.rows[0].next_seq).padStart(4, "0");
    const bordereauNumber = `BORD-${year}-${nextSequence}`;

    const bordereauResult = await query(
      `
      INSERT INTO reception_bordereaux (document_id, number)
      VALUES ($1, $2)
      RETURNING *
      `,
      [req.params.id, bordereauNumber]
    );

    return res.status(201).json({ bordereau: bordereauResult.rows[0], alreadyExists: false });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ error: "A bordereau conflict occurred. Please retry." });
    }
    return res.status(500).json({ error: "Failed to generate bordereau" });
  }
});

app.get("/reception/bordereaux", authRequired, requireRole(["ADMIN", "RECEPTION"]), async (req, res) => {
  try {
    const result = await query(
      `
      SELECT
        b.*,
        d.number AS document_number,
        d.subject AS document_subject
      FROM reception_bordereaux b
      JOIN reception_documents d ON d.id = b.document_id
      ORDER BY b.generated_at DESC
      `
    );

    const signedCount = result.rows.filter((item) => item.status === "Signé").length;
    const totalCount = result.rows.length;

    return res.json({
      totalCount,
      signedCount,
      unsignedCount: totalCount - signedCount,
      bordereaux: result.rows.map(sanitizeBordereau)
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to fetch bordereaux" });
  }
});

app.post("/reception/bordereaux/:id/mark-signed", authRequired, requireRole(["ADMIN", "RECEPTION"]), async (req, res) => {
  try {
    const result = await query(
      `
      UPDATE reception_bordereaux
      SET status = 'Signé',
          signed_at = NOW()
      WHERE id = $1
      RETURNING *
      `,
      [req.params.id]
    );

    const bordereau = result.rows[0];
    if (!bordereau) {
      return res.status(404).json({ error: "Bordereau not found" });
    }

    return res.json({
      bordereau: {
        id: bordereau.id,
        number: bordereau.number,
        status: bordereau.status,
        generatedAt: bordereau.generated_at,
        signedAt: bordereau.signed_at
      }
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to mark bordereau as signed" });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server listening on ${port}`);
});