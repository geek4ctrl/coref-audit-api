import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import multer from "multer";
import swaggerJSDoc from "swagger-jsdoc";
import swaggerUi from "swagger-ui-express";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { query } from "./config/database.js";
import "dotenv/config";

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

const swaggerSpec = swaggerJSDoc({
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Coref Audit API",
      version: "1.0.0"
    },
    servers: [
      {
        url: process.env.API_BASE_URL || "http://localhost:3000"
      }
    ]
  },
  apis: ["./src/server.js"]
});

app.use("/docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));
app.get("/docs.json", (_req, res) => res.json(swaggerSpec));

const messageUploadsDir = path.resolve(process.cwd(), "uploads", "messages");
if (!fs.existsSync(messageUploadsDir)) {
  fs.mkdirSync(messageUploadsDir, { recursive: true });
}

const documentUploadsDir = path.resolve(process.cwd(), "uploads", "documents");
if (!fs.existsSync(documentUploadsDir)) {
  fs.mkdirSync(documentUploadsDir, { recursive: true });
}

const messageUpload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, messageUploadsDir),
    filename: (_req, file, cb) => {
      const extension = path.extname(file.originalname || "");
      const randomSuffix = crypto.randomBytes(8).toString("hex");
      cb(null, `${Date.now()}-${randomSuffix}${extension}`);
    }
  }),
  limits: {
    fileSize: 10 * 1024 * 1024
  }
});

const documentUpload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, documentUploadsDir),
    filename: (_req, file, cb) => {
      const extension = path.extname(file.originalname || "");
      const randomSuffix = crypto.randomBytes(8).toString("hex");
      cb(null, `${Date.now()}-${randomSuffix}${extension}`);
    }
  }),
  limits: {
    fileSize: 10 * 1024 * 1024
  }
});

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

const sanitizeAssistantDocument = (document) => {
  const statusTone =
    document.assistant_status === "Terminé"
      ? "success"
      : document.assistant_status === "En cours"
        ? "warning"
        : "info";

  const isDelayed = document.delay_label === "En retard";

  return {
    id: document.id,
    number: document.number,
    object: document.subject,
    type: document.document_type,
    owner: "Assistant Chef",
    ownerRole: "Cabinet",
    status: document.assistant_status,
    statusTone,
    lastActionAt: document.last_action_at,
    lastActionNote: document.assistant_note || "Mise à jour en attente",
    delay: document.delay_label,
    delayTone: isDelayed ? "danger" : "muted",
    priority: document.assistant_priority,
    chiefDecision: document.chief_decision || null
  };
};

const sanitizeMessageAttachment = (attachment) => ({
  id: attachment.id,
  fileName: attachment.file_name,
  mimeType: attachment.mime_type,
  sizeBytes: attachment.size_bytes,
  createdAt: attachment.created_at
});

const sanitizeMessage = (message, attachments = []) => ({
  id: message.id,
  subject: message.subject,
  content: message.content,
  createdAt: message.created_at,
  readAt: message.read_at,
  sender: {
    id: message.sender_user_id,
    name: message.sender_name,
    email: message.sender_email
  },
  recipient: {
    id: message.recipient_user_id,
    name: message.recipient_name,
    email: message.recipient_email
  },
  attachments
});

const fetchAttachmentsForMessageIds = async (messageIds) => {
  if (!messageIds.length) {
    return new Map();
  }

  const result = await query(
    `
    SELECT *
    FROM message_attachments
    WHERE message_id = ANY($1)
    ORDER BY created_at ASC
    `,
    [messageIds]
  );

  const attachmentMap = new Map();
  for (const row of result.rows) {
    const existing = attachmentMap.get(row.message_id) || [];
    existing.push(sanitizeMessageAttachment(row));
    attachmentMap.set(row.message_id, existing);
  }

  return attachmentMap;
};

app.get("/", (req, res) => {
  res.send("API is running");
});

/**
 * @openapi
 * /:
 *   get:
 *     summary: API status
 *     tags:
 *       - Health
 *     responses:
 *       200:
 *         description: API is running
 */

app.get("/health/db", async (req, res) => {
  const result = await query("SELECT NOW() as now");
  res.json(result.rows[0]);
});

/**
 * @openapi
 * /health/db:
 *   get:
 *     summary: Database connectivity check
 *     tags:
 *       - Health
 *     responses:
 *       200:
 *         description: Database reachable
 */

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

/**
 * @openapi
 * /users:
 *   get:
 *     summary: List users
 *     tags:
 *       - Users
 *     responses:
 *       200:
 *         description: Users list
 */

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

/**
 * @openapi
 * /users/{id}:
 *   get:
 *     summary: Get a user by id
 *     tags:
 *       - Users
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: User details
 *       404:
 *         description: User not found
 */

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

/**
 * @openapi
 * /users:
 *   post:
 *     summary: Create a user
 *     tags:
 *       - Users
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - email
 *               - password
 *               - role
 *             properties:
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *               role:
 *                 type: string
 *               serviceId:
 *                 type: integer
 *               isActive:
 *                 type: boolean
 *     responses:
 *       201:
 *         description: User created
 */

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

/**
 * @openapi
 * /users/{id}:
 *   patch:
 *     summary: Update a user
 *     tags:
 *       - Users
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *               role:
 *                 type: string
 *               serviceId:
 *                 type: integer
 *               isActive:
 *                 type: boolean
 *     responses:
 *       200:
 *         description: User updated
 */

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

/**
 * @openapi
 * /users/{id}:
 *   delete:
 *     summary: Delete a user
 *     tags:
 *       - Users
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       204:
 *         description: Deleted
 *       404:
 *         description: User not found
 */

app.get("/messagerie/users", authRequired, requireRole(["ADMIN", "RECEPTION", "SERVICE_INTERNE", "CHEF_SG"]), async (req, res) => {
  try {
    const result = await query(
      `
      SELECT id, name, email
      FROM users
      WHERE is_active = TRUE
        AND id <> $1
      ORDER BY name ASC
      `,
      [req.user.userId]
    );

    return res.json({ users: result.rows });
  } catch (error) {
    return res.status(500).json({ error: "Failed to fetch recipients" });
  }
});

/**
 * @openapi
 * /messagerie/users:
 *   get:
 *     summary: List active messaging users
 *     tags:
 *       - Messaging
 *     responses:
 *       200:
 *         description: Users list
 */

app.get("/messagerie/inbox", authRequired, requireRole(["ADMIN", "RECEPTION", "SERVICE_INTERNE", "CHEF_SG"]), async (req, res) => {
  try {
    const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 50, 1), 100);
    const [result, unreadResult] = await Promise.all([
      query(
      `
      SELECT
        m.*,
        sender.name AS sender_name,
        sender.email AS sender_email,
        recipient.name AS recipient_name,
        recipient.email AS recipient_email
      FROM messages m
      JOIN users sender ON sender.id = m.sender_user_id
      JOIN users recipient ON recipient.id = m.recipient_user_id
      WHERE m.recipient_user_id = $1
      ORDER BY m.created_at DESC
      LIMIT $2
      `,
      [req.user.userId, limit]
      ),
      query(
        `
        SELECT COUNT(*)::INT AS unread_count
        FROM messages
        WHERE recipient_user_id = $1
          AND read_at IS NULL
        `,
        [req.user.userId]
      )
    ]);

    const messageIds = result.rows.map((row) => row.id);
    const attachmentMap = await fetchAttachmentsForMessageIds(messageIds);

    return res.json({
      unreadCount: unreadResult.rows[0]?.unread_count ?? 0,
      messages: result.rows.map((row) => sanitizeMessage(row, attachmentMap.get(row.id) || []))
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to fetch inbox" });
  }
});

/**
 * @openapi
 * /messagerie/inbox:
 *   get:
 *     summary: List inbox messages
 *     tags:
 *       - Messaging
 *     parameters:
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Inbox messages
 */

app.post("/messagerie/messages/:id/mark-read", authRequired, requireRole(["ADMIN", "RECEPTION", "SERVICE_INTERNE", "CHEF_SG"]), async (req, res) => {
  try {
    const result = await query(
      `
      UPDATE messages
      SET read_at = COALESCE(read_at, NOW())
      WHERE id = $1
        AND recipient_user_id = $2
      RETURNING *
      `,
      [req.params.id, req.user.userId]
    );

    const message = result.rows[0];
    if (!message) {
      return res.status(404).json({ error: "Message not found" });
    }

    return res.json({ message });
  } catch (error) {
    return res.status(500).json({ error: "Failed to mark message as read" });
  }
});

/**
 * @openapi
 * /messagerie/messages/{id}/mark-read:
 *   post:
 *     summary: Mark a message as read
 *     tags:
 *       - Messaging
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Updated message
 */

app.get("/messagerie/sent", authRequired, requireRole(["ADMIN", "RECEPTION", "SERVICE_INTERNE", "CHEF_SG"]), async (req, res) => {
  try {
    const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 50, 1), 100);
    const result = await query(
      `
      SELECT
        m.*,
        sender.name AS sender_name,
        sender.email AS sender_email,
        recipient.name AS recipient_name,
        recipient.email AS recipient_email
      FROM messages m
      JOIN users sender ON sender.id = m.sender_user_id
      JOIN users recipient ON recipient.id = m.recipient_user_id
      WHERE m.sender_user_id = $1
      ORDER BY m.created_at DESC
      LIMIT $2
      `,
      [req.user.userId, limit]
    );

    const messageIds = result.rows.map((row) => row.id);
    const attachmentMap = await fetchAttachmentsForMessageIds(messageIds);

    return res.json({
      messages: result.rows.map((row) => sanitizeMessage(row, attachmentMap.get(row.id) || []))
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to fetch sent messages" });
  }
});

/**
 * @openapi
 * /messagerie/sent:
 *   get:
 *     summary: List sent messages
 *     tags:
 *       - Messaging
 *     parameters:
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Sent messages
 */

app.post(
  "/messagerie/messages",
  authRequired,
  requireRole(["ADMIN", "RECEPTION", "SERVICE_INTERNE", "CHEF_SG"]),
  messageUpload.single("attachment"),
  async (req, res) => {
  try {
    const { recipientUserId, subject, content } = req.body || {};

    if (!recipientUserId || !subject || !content) {
      if (req.file?.path) {
        fs.unlink(req.file.path, () => undefined);
      }
      return res.status(400).json({ error: "recipientUserId, subject, and content are required" });
    }

    const recipientResult = await query(
      `
      SELECT id
      FROM users
      WHERE id = $1
        AND is_active = TRUE
      `,
      [recipientUserId]
    );

    if (!recipientResult.rows[0]) {
      if (req.file?.path) {
        fs.unlink(req.file.path, () => undefined);
      }
      return res.status(404).json({ error: "Recipient not found" });
    }

    const result = await query(
      `
      INSERT INTO messages (sender_user_id, recipient_user_id, subject, content)
      VALUES ($1, $2, $3, $4)
      RETURNING *
      `,
      [req.user.userId, Number(recipientUserId), subject.trim(), content.trim()]
    );

    const message = result.rows[0];

    if (req.file) {
      await query(
        `
        INSERT INTO message_attachments (message_id, file_name, mime_type, size_bytes, storage_path)
        VALUES ($1, $2, $3, $4, $5)
        `,
        [
          message.id,
          req.file.originalname,
          req.file.mimetype || "application/octet-stream",
          req.file.size,
          req.file.path
        ]
      );
    }

    return res.status(201).json({ message });
  } catch (error) {
    if (req.file?.path) {
      fs.unlink(req.file.path, () => undefined);
    }
    return res.status(500).json({ error: "Failed to send message" });
  }
});

app.get(
  "/messagerie/messages/:messageId/attachments/:attachmentId/download",
  authRequired,
  requireRole(["ADMIN", "RECEPTION", "SERVICE_INTERNE", "CHEF_SG"]),
  async (req, res) => {
    try {
      const result = await query(
        `
        SELECT
          a.*,
          m.sender_user_id,
          m.recipient_user_id
        FROM message_attachments a
        JOIN messages m ON m.id = a.message_id
        WHERE a.id = $1
          AND a.message_id = $2
        `,
        [req.params.attachmentId, req.params.messageId]
      );

      const attachment = result.rows[0];
      if (!attachment) {
        return res.status(404).json({ error: "Attachment not found" });
      }

      const isParticipant =
        Number(attachment.sender_user_id) === Number(req.user.userId) ||
        Number(attachment.recipient_user_id) === Number(req.user.userId);

      if (!isParticipant) {
        return res.status(403).json({ error: "Forbidden" });
      }

      if (!fs.existsSync(attachment.storage_path)) {
        return res.status(404).json({ error: "Attachment file missing" });
      }

      return res.download(attachment.storage_path, attachment.file_name);
    } catch (error) {
      return res.status(500).json({ error: "Failed to download attachment" });
    }
  }
);

/**
 * @openapi
 * /messagerie/messages:
 *   post:
 *     summary: Send a message
 *     tags:
 *       - Messaging
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             required:
 *               - recipientUserId
 *               - subject
 *               - content
 *             properties:
 *               recipientUserId:
 *                 type: integer
 *               subject:
 *                 type: string
 *               content:
 *                 type: string
 *               attachment:
 *                 type: string
 *                 format: binary
 *     responses:
 *       201:
 *         description: Message sent
 */

/**
 * @openapi
 * /messagerie/messages/{messageId}/attachments/{attachmentId}/download:
 *   get:
 *     summary: Download a message attachment
 *     tags:
 *       - Messaging
 *     parameters:
 *       - in: path
 *         name: messageId
 *         required: true
 *         schema:
 *           type: integer
 *       - in: path
 *         name: attachmentId
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: File download
 *       404:
 *         description: Not found
 */

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

/**
 * @openapi
 * /reception/documents/recent:
 *   get:
 *     summary: List recent reception documents
 *     tags:
 *       - Reception
 *     parameters:
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Recent documents
 */

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

/**
 * @openapi
 * /reception/dashboard/stats:
 *   get:
 *     summary: Reception dashboard stats
 *     tags:
 *       - Reception
 *     responses:
 *       200:
 *         description: Dashboard stats
 */

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

/**
 * @openapi
 * /reception/search:
 *   get:
 *     summary: Search reception documents
 *     tags:
 *       - Reception
 *     parameters:
 *       - in: query
 *         name: q
 *         schema:
 *           type: string
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Search results
 */

app.post("/reception/documents", authRequired, requireRole(["ADMIN", "RECEPTION"]), async (req, res) => {
  try {
    const {
      documentType,
      receivedDate,
      sender,
      subject,
      category,
      confidentiality,
      observations,
      priority
    } = req.body || {};

    if (!documentType || !receivedDate || !sender || !subject || !category || !confidentiality) {
      return res.status(400).json({
        error: "documentType, receivedDate, sender, subject, category, and confidentiality are required"
      });
    }

    const allowedPriorities = ["Basse", "Normale", "Haute", "Urgente"];
    const normalizedPriority = typeof priority === "string" && allowedPriorities.includes(priority.trim())
      ? priority.trim()
      : "Normale";

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
        assistant_priority,
        created_by_user_id
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
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
        normalizedPriority,
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

/**
 * @openapi
 * /reception/documents:
 *   post:
 *     summary: Create a reception document
 *     tags:
 *       - Reception
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - documentType
 *               - receivedDate
 *               - sender
 *               - subject
 *               - category
 *               - confidentiality
 *             properties:
 *               documentType:
 *                 type: string
 *               receivedDate:
 *                 type: string
 *               sender:
 *                 type: string
 *               subject:
 *                 type: string
 *               category:
 *                 type: string
 *               confidentiality:
 *                 type: string
 *               observations:
 *                 type: string
 *     responses:
 *       201:
 *         description: Document created
 */

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

/**
 * @openapi
 * /reception/distributions/overview:
 *   get:
 *     summary: Distribution overview
 *     tags:
 *       - Reception
 *     responses:
 *       200:
 *         description: Distribution overview
 */

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

/**
 * @openapi
 * /reception/distributions/{id}/mark-delivered:
 *   post:
 *     summary: Mark document delivered
 *     tags:
 *       - Reception
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Document updated
 */

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

/**
 * @openapi
 * /reception/distributions/{id}/generate-bordereau:
 *   post:
 *     summary: Generate a bordereau
 *     tags:
 *       - Reception
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       201:
 *         description: Bordereau created
 */

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

/**
 * @openapi
 * /reception/bordereaux:
 *   get:
 *     summary: List bordereaux
 *     tags:
 *       - Reception
 *     responses:
 *       200:
 *         description: Bordereaux list
 */

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

/**
 * @openapi
 * /reception/bordereaux/{id}/mark-signed:
 *   post:
 *     summary: Mark bordereau signed
 *     tags:
 *       - Reception
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Bordereau updated
 */

app.get("/assistant/dashboard", authRequired, requireRole(["ADMIN", "ASSISTANT_CHEF", "CHEF_SG"]), async (req, res) => {
  try {
    const limit = Math.min(Number.parseInt(req.query.limit, 10) || 25, 100);

    const [statsResult, documentsResult] = await Promise.all([
      query(
        `
        SELECT
          COUNT(*)::INT AS total_count,
          COUNT(*) FILTER (WHERE assistant_status = U&'\\00C0 traiter')::INT AS to_process_count,
          COUNT(*) FILTER (WHERE assistant_status = 'En cours')::INT AS in_progress_count,
          COUNT(*) FILTER (WHERE assistant_status = 'Terminé')::INT AS done_count,
          COUNT(*) FILTER (WHERE assistant_status = 'Envoyé au Chef')::INT AS sent_to_chief_count,
          COUNT(*) FILTER (
            WHERE assistant_treated_at IS NOT NULL
              AND assistant_treated_at >= date_trunc('week', NOW())
          )::INT AS treated_this_week_count,
          COUNT(*) FILTER (
            WHERE assistant_status <> 'Terminé'
              AND received_date < CURRENT_DATE - INTERVAL '3 days'
          )::INT AS delayed_count,
          COUNT(*) FILTER (
            WHERE (assistant_status = 'En cours' AND received_date < CURRENT_DATE - INTERVAL '7 days')
               OR (chief_decision = 'BLOQUER' AND assistant_status <> 'Terminé')
          )::INT AS blocked_count,
          COUNT(*) FILTER (
            WHERE assistant_priority IN ('Haute', 'Urgente')
              AND assistant_status <> 'Terminé'
          )::INT AS urgent_count
        FROM reception_documents
        `
      ),
      query(
        `
        SELECT
          id,
          number,
          document_type,
          subject,
          assistant_status,
          assistant_priority,
          assistant_note,
          received_date,
          created_at,
          COALESCE(assistant_treated_at, assistant_sent_to_chief_at, created_at) AS last_action_at,
          CASE
            WHEN assistant_status <> 'Terminé' AND received_date < CURRENT_DATE - INTERVAL '3 days' THEN 'En retard'
            ELSE '—'
          END AS delay_label
        FROM reception_documents
        ORDER BY
          CASE assistant_priority
            WHEN 'Urgente' THEN 0
            WHEN 'Haute' THEN 1
            WHEN 'Normale' THEN 2
            WHEN 'Basse' THEN 3
            ELSE 2
          END,
          created_at DESC
        LIMIT $1
        `,
        [limit]
      )
    ]);

    const stats = statsResult.rows[0] || {};

    return res.json({
      cards: {
        toReceive: stats.total_count || 0,
        toProcess: stats.to_process_count || 0,
        inProgress: stats.in_progress_count || 0,
        done: stats.done_count || 0,
        urgent: stats.urgent_count || 0
      },
      quickFilters: {
        all: stats.total_count || 0,
        toProcess: stats.to_process_count || 0,
        assignedToMe: stats.total_count || 0,
        sentByMe: stats.sent_to_chief_count || 0,
        noAck: stats.sent_to_chief_count || 0,
        delayed: stats.delayed_count || 0,
        blocked: stats.blocked_count || 0,
        treatedThisWeek: stats.treated_this_week_count || 0,
        urgent: stats.urgent_count || 0
      },
      documents: documentsResult.rows.map(sanitizeAssistantDocument)
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to fetch assistant dashboard" });
  }
});

/**
 * @openapi
 * /assistant/dashboard:
 *   get:
 *     summary: Assistant dashboard
 *     tags:
 *       - Assistant
 *     parameters:
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Dashboard data
 */

app.patch("/assistant/documents/:id/classify", authRequired, requireRole(["ADMIN", "ASSISTANT_CHEF", "CHEF_SG"]), async (req, res) => {
  try {
    const { priority, note, status } = req.body || {};

    const allowedPriorities = ["Basse", "Normale", "Haute", "Urgente"];
    if (priority && !allowedPriorities.includes(priority)) {
      return res.status(400).json({ error: "Invalid priority" });
    }

    const allowedStatuses = ["À traiter", "En cours"];
    if (status && !allowedStatuses.includes(status)) {
      return res.status(400).json({ error: "Invalid status" });
    }

    const result = await query(
      `
      UPDATE reception_documents
      SET assistant_priority = COALESCE($1, assistant_priority),
          assistant_note = COALESCE($2, assistant_note),
          assistant_status = COALESCE($3, 'En cours')
      WHERE id = $4
      RETURNING *
      `,
      [priority || null, note || null, status || null, req.params.id]
    );

    const document = result.rows[0];
    if (!document) {
      return res.status(404).json({ error: "Document not found" });
    }

    return res.json({
      document: {
        id: document.id,
        assistantStatus: document.assistant_status,
        assistantPriority: document.assistant_priority,
        assistantNote: document.assistant_note
      }
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to classify document" });
  }
});

/**
 * @openapi
 * /assistant/documents/{id}/classify:
 *   patch:
 *     summary: Classify a document
 *     tags:
 *       - Assistant
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               priority:
 *                 type: string
 *               note:
 *                 type: string
 *               status:
 *                 type: string
 *     responses:
 *       200:
 *         description: Document updated
 */

app.patch("/assistant/documents/:id/send-to-chief", authRequired, requireRole(["ADMIN", "ASSISTANT_CHEF", "CHEF_SG"]), async (req, res) => {
  try {
    const result = await query(
      `
      UPDATE reception_documents
      SET assistant_status = 'Envoyé au Chef',
          assistant_sent_to_chief_at = NOW()
      WHERE id = $1
      RETURNING id, assistant_status, assistant_sent_to_chief_at
      `,
      [req.params.id]
    );

    const document = result.rows[0];
    if (!document) {
      return res.status(404).json({ error: "Document not found" });
    }

    return res.json({
      document: {
        id: document.id,
        assistantStatus: document.assistant_status,
        sentToChiefAt: document.assistant_sent_to_chief_at
      }
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to send document to chief" });
  }
});

/**
 * @openapi
 * /assistant/documents/{id}/send-to-chief:
 *   patch:
 *     summary: Send document to chief
 *     tags:
 *       - Assistant
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Document updated
 */

app.patch("/assistant/documents/:id/mark-treated", authRequired, requireRole(["ADMIN", "ASSISTANT_CHEF", "CHEF_SG"]), async (req, res) => {
  try {
    const result = await query(
      `
      UPDATE reception_documents
      SET assistant_status = 'Terminé',
          assistant_treated_at = NOW()
      WHERE id = $1
      RETURNING id, assistant_status, assistant_treated_at
      `,
      [req.params.id]
    );

    const document = result.rows[0];
    if (!document) {
      return res.status(404).json({ error: "Document not found" });
    }

    return res.json({
      document: {
        id: document.id,
        assistantStatus: document.assistant_status,
        treatedAt: document.assistant_treated_at
      }
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to mark document as treated" });
  }
});

/**
 * @openapi
 * /assistant/documents/{id}/mark-treated:
 *   patch:
 *     summary: Mark document treated
 *     tags:
 *       - Assistant
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Document updated
 */

app.patch("/chief/documents/:id/decision", authRequired, requireRole(["ADMIN", "CHEF_SG"]), async (req, res) => {
  try {
    const {
      decision,
      assignedToType,
      assignedToValue,
      priority,
      slaDays,
      instruction
    } = req.body || {};

    const normalizedDecision = typeof decision === "string" ? decision.trim().toUpperCase() : "";
    const allowedDecisions = ["ASSIGN_PILIER", "ASSIGN_SERVICE", "SEND_SECRETARIAT", "CLOSE", "BLOQUER"];

    if (!allowedDecisions.includes(normalizedDecision)) {
      return res.status(400).json({ error: "Invalid decision" });
    }

    if ((normalizedDecision === "ASSIGN_PILIER" || normalizedDecision === "ASSIGN_SERVICE") && (!assignedToValue || !String(assignedToValue).trim())) {
      return res.status(400).json({ error: "assignedToValue is required for assignment decisions" });
    }

    const normalizedAssignedType =
      normalizedDecision === "ASSIGN_PILIER"
        ? "PILIER"
        : normalizedDecision === "ASSIGN_SERVICE"
          ? "SERVICE"
          : normalizedDecision === "SEND_SECRETARIAT"
            ? "SECRETARIAT"
            : null;

    const normalizedAssignedValue =
      normalizedDecision === "ASSIGN_PILIER" || normalizedDecision === "ASSIGN_SERVICE"
        ? String(assignedToValue || "").trim() || null
        : normalizedDecision === "SEND_SECRETARIAT"
          ? "SECRETARIAT"
          : null;

    const normalizedPriority = typeof priority === "string" && priority.trim() ? priority.trim() : null;
    const normalizedInstruction = typeof instruction === "string" && instruction.trim() ? instruction.trim() : null;
    const normalizedSlaDays = Number.isFinite(Number(slaDays)) ? Number(slaDays) : null;

    if (normalizedSlaDays !== null && (normalizedSlaDays < 0 || normalizedSlaDays > 365)) {
      return res.status(400).json({ error: "slaDays must be between 0 and 365" });
    }

    const assistantStatus = normalizedDecision === "CLOSE" ? "Terminé" : "En cours";
    const shouldSetTreatedAt = normalizedDecision === "CLOSE";

    const result = await query(
      `
      UPDATE reception_documents
      SET chief_decision = $1,
          chief_assigned_to_type = $2,
          chief_assigned_to_value = $3,
          chief_priority = COALESCE($4, chief_priority),
          chief_sla_days = $5,
          chief_instruction = COALESCE($6, chief_instruction),
          chief_decided_at = NOW(),
          chief_decided_by_user_id = $7,
          assistant_status = $8,
          assistant_treated_at = CASE WHEN $9 THEN NOW() ELSE assistant_treated_at END,
          assistant_note = COALESCE($10, assistant_note)
      WHERE id = $11
      RETURNING id, number, assistant_status, chief_decision, chief_assigned_to_type, chief_assigned_to_value, chief_priority, chief_sla_days, chief_instruction, chief_decided_at
      `,
      [
        normalizedDecision,
        normalizedAssignedType,
        normalizedAssignedValue,
        normalizedPriority,
        normalizedSlaDays,
        normalizedInstruction,
        req.user.userId,
        assistantStatus,
        shouldSetTreatedAt,
        normalizedDecision === "BLOQUER" ? "En attente d'informations complémentaires" : null,
        req.params.id
      ]
    );

    const document = result.rows[0];
    if (!document) {
      return res.status(404).json({ error: "Document not found" });
    }

    return res.json({
      document: {
        id: document.id,
        number: document.number,
        assistantStatus: document.assistant_status,
        decision: document.chief_decision,
        assignedToType: document.chief_assigned_to_type,
        assignedToValue: document.chief_assigned_to_value,
        priority: document.chief_priority,
        slaDays: document.chief_sla_days,
        instruction: document.chief_instruction,
        decidedAt: document.chief_decided_at
      }
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to save chief decision" });
  }
});

// ── SERVICE INTERNE ENDPOINTS ──

const sanitizePilierDocument = (doc) => {
  const statusMap = {
    ENVOYE: "info",
    RECU: "info",
    EN_TRAITEMENT: "warning",
    FINALISE: "success",
    ENVOYE_COORDINATEUR: "info",
    VALIDE: "success",
    REJETE: "warning"
  };
  return {
    id: doc.id,
    number: doc.number,
    object: doc.subject,
    type: doc.document_type || doc.category,
    status: doc.pilier_status || "ENVOYE",
    statusTone: statusMap[doc.pilier_status] || "info",
    sender: doc.sender,
    category: doc.category,
    chiefPriority: doc.chief_priority,
    assistantPriority: doc.assistant_priority,
    priority: doc.chief_priority || doc.assistant_priority || 'Normale',
    chiefInstruction: doc.chief_instruction,
    chiefSlaDays: doc.chief_sla_days,
    chiefDecidedAt: doc.chief_decided_at,
    pilierNote: doc.pilier_note,
    pilierAcknowledgedAt: doc.pilier_acknowledged_at,
    pilierStartedAt: doc.pilier_started_at,
    pilierFinalizedAt: doc.pilier_finalized_at,
    pilierSentToCoordinatorAt: doc.pilier_sent_to_coordinator_at,
    coordinatorStatus: doc.coordinator_status,
    coordinatorComment: doc.coordinator_comment,
    coordinatorValidatedAt: doc.coordinator_validated_at,
    coordinatorRejectedAt: doc.coordinator_rejected_at,
    lastActionAt: doc.pilier_sent_to_coordinator_at || doc.pilier_finalized_at || doc.pilier_started_at || doc.pilier_acknowledged_at || doc.chief_decided_at || doc.created_at,
    deadline: doc.chief_sla_days && doc.chief_decided_at
      ? new Date(new Date(doc.chief_decided_at).getTime() + doc.chief_sla_days * 86400000).toISOString()
      : null,
    createdAt: doc.created_at
  };
};

app.get("/service/dashboard", authRequired, requireRole(["ADMIN", "SERVICE_INTERNE"]), async (req, res) => {
  try {
    const whereClause = "WHERE chief_decision = 'ASSIGN_SERVICE'";
    const params = [];

    const [statsResult, documentsResult] = await Promise.all([
      query(
        `SELECT
          COUNT(*) FILTER (WHERE pilier_status IS NULL OR pilier_status = 'ENVOYE')::INT AS to_receive,
          COUNT(*) FILTER (WHERE pilier_status IN ('RECU', 'EN_TRAITEMENT'))::INT AS in_progress,
          COUNT(*) FILTER (WHERE pilier_status = 'ENVOYE_COORDINATEUR')::INT AS at_coordinator,
          COUNT(*) FILTER (WHERE coordinator_status = 'VALIDE')::INT AS done,
          COUNT(*) FILTER (
            WHERE (pilier_status NOT IN ('FINALISE') OR pilier_status IS NULL)
            AND chief_sla_days IS NOT NULL
            AND chief_decided_at IS NOT NULL
            AND chief_decided_at + (chief_sla_days || ' days')::INTERVAL < NOW()
          )::INT AS late
        FROM reception_documents
        ${whereClause}`,
        params
      ),
      query(
        `SELECT * FROM reception_documents
        ${whereClause}
        ORDER BY
          CASE WHEN pilier_status IS NULL OR pilier_status = 'ENVOYE' THEN 0
               WHEN pilier_status IN ('RECU', 'EN_TRAITEMENT') THEN 1
               WHEN pilier_status = 'ENVOYE_COORDINATEUR' THEN 2
               ELSE 3 END,
          CASE chief_priority
            WHEN 'Urgente' THEN 0
            WHEN 'Haute' THEN 1
            WHEN 'Normale' THEN 2
            WHEN 'Basse' THEN 3
            ELSE 2
          END,
          created_at DESC
        LIMIT 50`,
        params
      )
    ]);

    const stats = statsResult.rows[0] || {};
    const categoryMap = {
      "a-receptionner": (d) => !d.pilier_status || d.pilier_status === "ENVOYE",
      "en-traitement": (d) => d.pilier_status === "RECU" || d.pilier_status === "EN_TRAITEMENT" || d.pilier_status === "FINALISE",
      "chez-coordinateur": (d) => d.pilier_status === "ENVOYE_COORDINATEUR",
      "termines": (d) => d.coordinator_status === "VALIDE" || (d.pilier_status === "FINALISE" && d.assistant_status === "\u00C0 traiter")
    };

    const documents = documentsResult.rows.map((doc) => {
      const sanitized = sanitizePilierDocument(doc);
      let category = "a-receptionner";
      for (const [key, fn] of Object.entries(categoryMap)) {
        if (fn(doc)) { category = key; break; }
      }
      return { ...sanitized, category };
    });

    return res.json({
      cards: {
        toReceive: stats.to_receive || 0,
        inProgress: stats.in_progress || 0,
        atCoordinator: stats.at_coordinator || 0,
        late: stats.late || 0
      },
      serviceName: req.user.name || "",
      documents
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to fetch service dashboard" });
  }
});

app.patch("/service/documents/:id/acknowledge", authRequired, requireRole(["ADMIN", "SERVICE_INTERNE"]), async (req, res) => {
  try {
    const result = await query(
      `UPDATE reception_documents SET pilier_status = 'RECU', pilier_acknowledged_at = NOW(), pilier_user_id = $1 WHERE id = $2 AND chief_decision = 'ASSIGN_SERVICE' RETURNING *`,
      [req.user.id, req.params.id]
    );
    const doc = result.rows[0];
    if (!doc) return res.status(404).json({ error: "Document not found" });
    return res.json({ document: sanitizePilierDocument(doc) });
  } catch (error) {
    return res.status(500).json({ error: "Failed to acknowledge document" });
  }
});

app.patch("/service/documents/:id/start-processing", authRequired, requireRole(["ADMIN", "SERVICE_INTERNE"]), async (req, res) => {
  try {
    const result = await query(
      `UPDATE reception_documents SET pilier_status = 'EN_TRAITEMENT', pilier_started_at = NOW() WHERE id = $1 AND chief_decision = 'ASSIGN_SERVICE' RETURNING *`,
      [req.params.id]
    );
    const doc = result.rows[0];
    if (!doc) return res.status(404).json({ error: "Document not found" });
    return res.json({ document: sanitizePilierDocument(doc) });
  } catch (error) {
    return res.status(500).json({ error: "Failed to start processing" });
  }
});

app.patch("/service/documents/:id/finalize", authRequired, requireRole(["ADMIN", "SERVICE_INTERNE"]), async (req, res) => {
  try {
    const result = await query(
      `UPDATE reception_documents SET pilier_status = 'FINALISE', pilier_finalized_at = NOW() WHERE id = $1 AND chief_decision = 'ASSIGN_SERVICE' RETURNING *`,
      [req.params.id]
    );
    const doc = result.rows[0];
    if (!doc) return res.status(404).json({ error: "Document not found" });
    return res.json({ document: sanitizePilierDocument(doc) });
  } catch (error) {
    return res.status(500).json({ error: "Failed to finalize document" });
  }
});

app.patch("/service/documents/:id/send-to-coordinator", authRequired, requireRole(["ADMIN", "SERVICE_INTERNE"]), async (req, res) => {
  try {
    const result = await query(
      `UPDATE reception_documents SET pilier_status = 'ENVOYE_COORDINATEUR', pilier_sent_to_coordinator_at = NOW(), coordinator_status = 'EN_ATTENTE_VALIDATION' WHERE id = $1 AND chief_decision = 'ASSIGN_SERVICE' RETURNING *`,
      [req.params.id]
    );
    const doc = result.rows[0];
    if (!doc) return res.status(404).json({ error: "Document not found" });
    return res.json({ document: sanitizePilierDocument(doc) });
  } catch (error) {
    return res.status(500).json({ error: "Failed to send to coordinator" });
  }
});

app.patch("/service/documents/:id/send-to-assistant", authRequired, requireRole(["ADMIN", "SERVICE_INTERNE"]), async (req, res) => {
  try {
    const result = await query(
      `UPDATE reception_documents
       SET pilier_status = 'FINALISE',
           pilier_finalized_at = COALESCE(pilier_finalized_at, NOW()),
           assistant_status = U&'\\00C0 traiter'
       WHERE id = $1 AND chief_decision = 'ASSIGN_SERVICE'
       RETURNING *`,
      [req.params.id]
    );
    const doc = result.rows[0];
    if (!doc) return res.status(404).json({ error: "Document not found" });
    return res.json({ document: sanitizePilierDocument(doc) });
  } catch (error) {
    return res.status(500).json({ error: "Failed to send to assistant" });
  }
});

// ── PILIER ENDPOINTS ──

app.get("/pilier/dashboard", authRequired, requireRole(["ADMIN", "PILIER", "PILIER_COORD"]), async (req, res) => {
  try {
    const userId = req.user.id;
    const userRole = req.user.role;

    let whereClause;
    let params;

    if (userRole === "ADMIN") {
      whereClause = "WHERE chief_decision = 'ASSIGN_PILIER'";
      params = [];
    } else {
      whereClause = "WHERE chief_decision = 'ASSIGN_PILIER' AND (pilier_user_id = $1 OR chief_assigned_to_value = $1::TEXT)";
      params = [userId];
    }

    const [statsResult, documentsResult] = await Promise.all([
      query(
        `SELECT
          COUNT(*) FILTER (WHERE pilier_status IS NULL OR pilier_status = 'ENVOYE')::INT AS to_receive,
          COUNT(*) FILTER (WHERE pilier_status IN ('RECU', 'EN_TRAITEMENT') AND (coordinator_status IS NULL OR coordinator_status != 'REJETE'))::INT AS in_progress,
          COUNT(*) FILTER (WHERE pilier_status = 'ENVOYE_COORDINATEUR')::INT AS at_coordinator,
          COUNT(*) FILTER (WHERE pilier_status IN ('FINALISE', 'ENVOYE_COORDINATEUR') AND coordinator_status = 'VALIDE')::INT AS done,
          COUNT(*) FILTER (WHERE coordinator_status = 'REJETE' AND pilier_status = 'EN_TRAITEMENT')::INT AS rejected,
          COUNT(*) FILTER (
            WHERE pilier_status NOT IN ('FINALISE') OR pilier_status IS NULL
            AND chief_sla_days IS NOT NULL
            AND chief_decided_at IS NOT NULL
            AND chief_decided_at + (chief_sla_days || ' days')::INTERVAL < NOW()
          )::INT AS late
        FROM reception_documents
        ${whereClause}`,
        params
      ),
      query(
        `SELECT * FROM reception_documents
        ${whereClause}
        ORDER BY
          CASE WHEN pilier_status IS NULL OR pilier_status = 'ENVOYE' THEN 0
               WHEN pilier_status IN ('RECU', 'EN_TRAITEMENT') THEN 1
               WHEN pilier_status = 'ENVOYE_COORDINATEUR' THEN 2
               ELSE 3 END,
          CASE chief_priority
            WHEN 'Urgente' THEN 0
            WHEN 'Haute' THEN 1
            WHEN 'Normale' THEN 2
            WHEN 'Basse' THEN 3
            ELSE 2
          END,
          created_at DESC
        LIMIT 50`,
        params
      )
    ]);

    const stats = statsResult.rows[0] || {};
    const categoryMap = {
      "a-receptionner": (d) => !d.pilier_status || d.pilier_status === "ENVOYE",
      "en-traitement": (d) => (d.pilier_status === "RECU" || d.pilier_status === "EN_TRAITEMENT") && d.coordinator_status !== "REJETE",
      "retour-correction": (d) => d.coordinator_status === "REJETE" && d.pilier_status === "EN_TRAITEMENT",
      "chez-coordinateur": (d) => d.pilier_status === "ENVOYE_COORDINATEUR" || d.pilier_status === "FINALISE",
      "termines": (d) => d.coordinator_status === "VALIDE"
    };

    const documents = documentsResult.rows.map((doc) => {
      const sanitized = sanitizePilierDocument(doc);
      let category = "a-receptionner";
      for (const [key, fn] of Object.entries(categoryMap)) {
        if (fn(doc)) { category = key; break; }
      }
      return { ...sanitized, category };
    });

    return res.json({
      cards: {
        toReceive: stats.to_receive || 0,
        inProgress: stats.in_progress || 0,
        atCoordinator: stats.at_coordinator || 0,
        rejected: stats.rejected || 0,
        late: stats.late || 0
      },
      serviceName: req.user.service_name || "",
      documents
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to fetch pilier dashboard" });
  }
});

app.get("/pilier/documents/:id", authRequired, requireRole(["ADMIN", "PILIER", "PILIER_COORD"]), async (req, res) => {
  try {
    const result = await query("SELECT * FROM reception_documents WHERE id = $1", [req.params.id]);
    const doc = result.rows[0];
    if (!doc) return res.status(404).json({ error: "Document not found" });
    return res.json({ document: sanitizePilierDocument(doc) });
  } catch (error) {
    return res.status(500).json({ error: "Failed to fetch document" });
  }
});

app.patch("/pilier/documents/:id/acknowledge", authRequired, requireRole(["ADMIN", "PILIER"]), async (req, res) => {
  try {
    const result = await query(
      `UPDATE reception_documents
       SET pilier_status = 'RECU',
           pilier_acknowledged_at = NOW(),
           pilier_user_id = COALESCE(pilier_user_id, $2)
       WHERE id = $1 AND (pilier_status IS NULL OR pilier_status = 'ENVOYE')
       RETURNING *`,
      [req.params.id, req.user.id]
    );
    const doc = result.rows[0];
    if (!doc) return res.status(404).json({ error: "Document not found or already acknowledged" });
    return res.json({ document: sanitizePilierDocument(doc) });
  } catch (error) {
    return res.status(500).json({ error: "Failed to acknowledge document" });
  }
});

app.patch("/pilier/documents/:id/start-processing", authRequired, requireRole(["ADMIN", "PILIER"]), async (req, res) => {
  try {
    const result = await query(
      `UPDATE reception_documents
       SET pilier_status = 'EN_TRAITEMENT',
           pilier_started_at = NOW()
       WHERE id = $1 AND pilier_status = 'RECU'
       RETURNING *`,
      [req.params.id]
    );
    const doc = result.rows[0];
    if (!doc) return res.status(404).json({ error: "Document not found or not in correct state" });
    return res.json({ document: sanitizePilierDocument(doc) });
  } catch (error) {
    return res.status(500).json({ error: "Failed to start processing" });
  }
});

app.patch("/pilier/documents/:id/finalize", authRequired, requireRole(["ADMIN", "PILIER"]), async (req, res) => {
  try {
    const { note } = req.body || {};
    const result = await query(
      `UPDATE reception_documents
       SET pilier_status = 'FINALISE',
           pilier_finalized_at = NOW(),
           pilier_note = COALESCE($2, pilier_note)
       WHERE id = $1 AND pilier_status = 'EN_TRAITEMENT'
       RETURNING *`,
      [req.params.id, typeof note === "string" ? note.trim() || null : null]
    );
    const doc = result.rows[0];
    if (!doc) return res.status(404).json({ error: "Document not found or not in correct state" });
    return res.json({ document: sanitizePilierDocument(doc) });
  } catch (error) {
    return res.status(500).json({ error: "Failed to finalize document" });
  }
});

app.patch("/pilier/documents/:id/send-to-coordinator", authRequired, requireRole(["ADMIN", "PILIER"]), async (req, res) => {
  try {
    const result = await query(
      `UPDATE reception_documents
       SET pilier_status = 'ENVOYE_COORDINATEUR',
           pilier_sent_to_coordinator_at = NOW(),
           coordinator_status = 'EN_ATTENTE_VALIDATION'
       WHERE id = $1 AND pilier_status = 'FINALISE'
       RETURNING *`,
      [req.params.id]
    );
    const doc = result.rows[0];
    if (!doc) return res.status(404).json({ error: "Document not found or not finalized" });
    return res.json({ document: sanitizePilierDocument(doc) });
  } catch (error) {
    return res.status(500).json({ error: "Failed to send to coordinator" });
  }
});

// ── COORDINATOR ENDPOINTS ──

app.get("/coordinator/dashboard", authRequired, requireRole(["ADMIN", "PILIER_COORD"]), async (req, res) => {
  try {
    const [statsResult, documentsResult, historyResult] = await Promise.all([
      query(
        `SELECT
          COUNT(*) FILTER (WHERE coordinator_status = 'EN_ATTENTE_VALIDATION')::INT AS pending,
          COUNT(*) FILTER (WHERE coordinator_status = 'VALIDE')::INT AS validated,
          COUNT(*) FILTER (WHERE coordinator_status = 'REJETE')::INT AS rejected,
          COUNT(*) FILTER (
            WHERE coordinator_status = 'EN_ATTENTE_VALIDATION'
              AND chief_priority IN ('Haute', 'Urgente')
          )::INT AS urgent,
          COUNT(*) FILTER (
            WHERE coordinator_status = 'EN_ATTENTE_VALIDATION'
              AND chief_sla_days IS NOT NULL AND chief_decided_at IS NOT NULL
              AND chief_decided_at + (chief_sla_days || ' days')::INTERVAL < NOW()
          )::INT AS late
        FROM reception_documents
        WHERE coordinator_status IS NOT NULL`
      ),
      query(
        `SELECT * FROM reception_documents
         WHERE coordinator_status IN ('EN_ATTENTE_VALIDATION', 'VALIDE', 'REJETE')
         ORDER BY
           CASE coordinator_status
             WHEN 'EN_ATTENTE_VALIDATION' THEN 0
             WHEN 'REJETE' THEN 1
             ELSE 2
           END,
           CASE chief_priority
             WHEN 'Urgente' THEN 0 WHEN 'Haute' THEN 1 WHEN 'Normale' THEN 2 ELSE 3
           END,
           pilier_sent_to_coordinator_at DESC NULLS LAST
         LIMIT 50`
      ),
      query(
        `SELECT * FROM reception_documents
         WHERE coordinator_status = 'VALIDE'
           AND coordinator_validated_at >= NOW() - INTERVAL '7 days'
         ORDER BY coordinator_validated_at DESC
         LIMIT 10`
      )
    ]);

    const stats = statsResult.rows[0] || {};

    const categoryMap = {
      "a-valider": (d) => d.coordinator_status === "EN_ATTENTE_VALIDATION",
      "rejetes": (d) => d.coordinator_status === "REJETE",
      "valides": (d) => d.coordinator_status === "VALIDE"
    };

    const documents = documentsResult.rows.map((doc) => {
      const sanitized = sanitizePilierDocument(doc);
      let category = "a-valider";
      for (const [key, fn] of Object.entries(categoryMap)) {
        if (fn(doc)) { category = key; break; }
      }
      return { ...sanitized, category };
    });

    const recentValidated = historyResult.rows.map(sanitizePilierDocument);

    return res.json({
      cards: {
        pending: stats.pending || 0,
        validated: stats.validated || 0,
        rejected: stats.rejected || 0,
        urgent: stats.urgent || 0,
        late: stats.late || 0
      },
      documents,
      recentValidated
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to fetch coordinator dashboard" });
  }
});

app.get("/coordinator/documents", authRequired, requireRole(["ADMIN", "PILIER_COORD"]), async (req, res) => {
  try {
    const result = await query(
      `SELECT * FROM reception_documents
       WHERE coordinator_status = 'EN_ATTENTE_VALIDATION'
       ORDER BY
         CASE chief_priority
           WHEN 'Urgente' THEN 0 WHEN 'Haute' THEN 1 WHEN 'Normale' THEN 2 ELSE 3
         END,
         pilier_sent_to_coordinator_at DESC
       LIMIT 50`
    );
    return res.json({ documents: result.rows.map(sanitizePilierDocument) });
  } catch (error) {
    return res.status(500).json({ error: "Failed to fetch coordinator documents" });
  }
});

app.patch("/coordinator/documents/:id/validate", authRequired, requireRole(["ADMIN", "PILIER_COORD"]), async (req, res) => {
  try {
    const { comment } = req.body || {};
    const result = await query(
      `UPDATE reception_documents
       SET coordinator_status = 'VALIDE',
           coordinator_validated_at = NOW(),
           coordinator_comment = $2,
           coordinator_user_id = $3,
           assistant_status = U&'\\00C0 traiter'
       WHERE id = $1 AND coordinator_status = 'EN_ATTENTE_VALIDATION'
       RETURNING *`,
      [
        req.params.id,
        typeof comment === "string" ? comment.trim() || null : null,
        req.user.id
      ]
    );
    const doc = result.rows[0];
    if (!doc) return res.status(404).json({ error: "Document not found or not pending validation" });
    return res.json({ document: sanitizePilierDocument(doc) });
  } catch (error) {
    return res.status(500).json({ error: "Failed to validate document" });
  }
});

app.patch("/coordinator/documents/:id/reject", authRequired, requireRole(["ADMIN", "PILIER_COORD"]), async (req, res) => {
  try {
    const { comment } = req.body || {};
    if (!comment || !comment.trim()) {
      return res.status(400).json({ error: "A comment is required when rejecting" });
    }
    const result = await query(
      `UPDATE reception_documents
       SET coordinator_status = 'REJETE',
           coordinator_rejected_at = NOW(),
           coordinator_comment = $2,
           coordinator_user_id = $3,
           pilier_status = 'EN_TRAITEMENT',
           pilier_finalized_at = NULL,
           pilier_sent_to_coordinator_at = NULL
       WHERE id = $1 AND coordinator_status = 'EN_ATTENTE_VALIDATION'
       RETURNING *`,
      [req.params.id, comment.trim(), req.user.id]
    );
    const doc = result.rows[0];
    if (!doc) return res.status(404).json({ error: "Document not found or not pending validation" });
    return res.json({ document: sanitizePilierDocument(doc) });
  } catch (error) {
    return res.status(500).json({ error: "Failed to reject document" });
  }
});

/**
 * @openapi
 * /chief/documents/{id}/decision:
 *   patch:
 *     summary: Save chief decision
 *     tags:
 *       - Chief
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               decision:
 *                 type: string
 *               assignedToType:
 *                 type: string
 *               assignedToValue:
 *                 type: string
 *               priority:
 *                 type: string
 *               slaDays:
 *                 type: integer
 *               instruction:
 *                 type: string
 *     responses:
 *       200:
 *         description: Decision saved
 */

// ── Secrétariat endpoints ──

app.get("/secretariat/users", authRequired, requireRole(["ADMIN", "SECRETARIAT", "CHEF_SG", "ASSISTANT_CHEF"]), async (req, res) => {
  try {
    const result = await query(
      `SELECT id, name, role FROM users WHERE is_active = TRUE ORDER BY name`
    );
    return res.json({ users: result.rows });
  } catch (error) {
    return res.status(500).json({ error: "Failed to load users" });
  }
});

app.post("/secretariat/send-document", authRequired, requireRole(["ADMIN", "SECRETARIAT"]), documentUpload.single("file"), async (req, res) => {
  try {
    const { subject, type, priority, sender, receptionDate, assignTo, processingDelay, comment } = req.body;
    if (!subject || !assignTo) {
      return res.status(400).json({ error: "Subject and assignTo are required" });
    }

    const number = `COREF-${new Date().getFullYear()}-${String(Date.now()).slice(-6)}`;
    const result = await query(
      `INSERT INTO reception_documents (number, document_type, received_date, sender, subject, category, confidentiality, status, created_by_user_id, observations)
       VALUES ($1, $2, COALESCE($3::date, CURRENT_DATE), COALESCE($4, 'Secrétariat'), $5, 'COURRIER_DEPART', 'Normal', 'Document envoyé', $6, $7)
       RETURNING *`,
      [
        number,
        type || "Courrier d'arrivée",
        receptionDate || null,
        sender || null,
        subject.trim(),
        req.user.id,
        comment || null
      ]
    );

    return res.status(201).json({ document: { id: result.rows[0].id, number } });
  } catch (error) {
    return res.status(500).json({ error: "Failed to create and send document", detail: error.message });
  }
});

app.post("/secretariat/route-document", authRequired, requireRole(["ADMIN", "SECRETARIAT"]), async (req, res) => {
  try {
    const { searchQuery, assignTo, comment } = req.body;
    if (!searchQuery || !assignTo) {
      return res.status(400).json({ error: "searchQuery and assignTo are required" });
    }

    const findResult = await query(
      `SELECT id FROM reception_documents
       WHERE number ILIKE $1 OR subject ILIKE $1
       ORDER BY created_at DESC
       LIMIT 1`,
      [`%${searchQuery.trim()}%`]
    );

    if (findResult.rows.length === 0) {
      return res.status(404).json({ error: "Document not found" });
    }

    const docId = findResult.rows[0].id;
    await query(
      `UPDATE reception_documents
       SET status = 'Document envoyé',
           observations = COALESCE(observations || E'\\n', '') || $2
       WHERE id = $1`,
      [docId, comment ? `[Routé] ${comment.trim()}` : '[Routé par secrétariat]']
    );

    return res.json({ document: { id: docId } });
  } catch (error) {
    return res.status(500).json({ error: "Failed to route document", detail: error.message });
  }
});

app.get("/secretariat/dashboard", authRequired, requireRole(["ADMIN", "SECRETARIAT"]), async (req, res) => {
  try {
    const toFormatResult = await query(
      `SELECT COUNT(*) FROM reception_documents
       WHERE chief_decision = 'SEND_SECRETARIAT'
         AND (secretariat_status IS NULL OR secretariat_status = 'A_FORMATER')`
    );
    const formattedTodayResult = await query(
      `SELECT COUNT(*) FROM reception_documents
       WHERE secretariat_status = 'FORMATE'
         AND secretariat_formatted_at::date = CURRENT_DATE`
    );
    const sentToAssistantResult = await query(
      `SELECT COUNT(*) FROM reception_documents
       WHERE secretariat_status = 'ENVOYE_ASSISTANTE'`
    );
    const returnedResult = await query(
      `SELECT COUNT(*) FROM reception_documents
       WHERE secretariat_status = 'RETOUR_CORRECTION'`
    );

    const documentsResult = await query(
      `SELECT id, number, subject, sender, document_type, received_date, status,
              secretariat_status, assistant_priority, chief_priority, created_at
       FROM reception_documents
       WHERE chief_decision = 'SEND_SECRETARIAT'
         AND (secretariat_status IS NULL OR secretariat_status = 'A_FORMATER' OR secretariat_status = 'RETOUR_CORRECTION')
       ORDER BY
         CASE COALESCE(chief_priority, assistant_priority)
           WHEN 'Urgente' THEN 0
           WHEN 'Haute' THEN 1
           WHEN 'Normale' THEN 2
           WHEN 'Basse' THEN 3
           ELSE 2
         END,
         created_at DESC
       LIMIT 20`
    );

    const formattedDocsResult = await query(
      `SELECT id, number, subject, sender, document_type, received_date, status,
              secretariat_status, secretariat_formatted_at, assistant_priority, chief_priority, created_at
       FROM reception_documents
       WHERE chief_decision = 'SEND_SECRETARIAT'
         AND secretariat_status = 'FORMATE'
       ORDER BY
         CASE COALESCE(chief_priority, assistant_priority)
           WHEN 'Urgente' THEN 0
           WHEN 'Haute' THEN 1
           WHEN 'Normale' THEN 2
           WHEN 'Basse' THEN 3
           ELSE 2
         END,
         secretariat_formatted_at DESC
       LIMIT 20`
    );

    const documents = documentsResult.rows.map(row => ({
      id: row.id,
      number: row.number,
      object: row.subject,
      sender: row.sender,
      owner: row.sender,
      type: row.document_type,
      status: row.secretariat_status === 'RETOUR_CORRECTION' ? 'Retour correction' : 'À formater',
      statusTone: row.secretariat_status === 'RETOUR_CORRECTION' ? 'danger' : 'warning',
      priority: row.chief_priority || row.assistant_priority || 'Normale',
      receivedDate: row.received_date,
      lastActionAt: row.created_at
    }));

    const formattedDocuments = formattedDocsResult.rows.map(row => ({
      id: row.id,
      number: row.number,
      object: row.subject,
      sender: row.sender,
      owner: row.sender,
      type: row.document_type,
      status: 'Formaté',
      statusTone: 'success',
      priority: row.chief_priority || row.assistant_priority || 'Normale',
      receivedDate: row.received_date,
      lastActionAt: row.secretariat_formatted_at || row.created_at
    }));

    return res.json({
      cards: {
        toFormat: parseInt(toFormatResult.rows[0].count),
        formattedToday: parseInt(formattedTodayResult.rows[0].count),
        sentToAssistant: parseInt(sentToAssistantResult.rows[0].count),
        returnedForCorrection: parseInt(returnedResult.rows[0].count)
      },
      documents,
      formattedDocuments
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to load secretariat dashboard", detail: error.message });
  }
});

app.patch("/secretariat/documents/:id/format", authRequired, requireRole(["ADMIN", "SECRETARIAT"]), async (req, res) => {
  try {
    const result = await query(
      `UPDATE reception_documents
       SET secretariat_status = 'FORMATE',
           secretariat_formatted_at = NOW(),
           secretariat_user_id = $2
       WHERE id = $1
         AND chief_decision = 'SEND_SECRETARIAT'
         AND (secretariat_status IS NULL OR secretariat_status = 'A_FORMATER' OR secretariat_status = 'RETOUR_CORRECTION')
       RETURNING *`,
      [req.params.id, req.user.id]
    );
    const doc = result.rows[0];
    if (!doc) return res.status(404).json({ error: "Document not found or not in correct state" });
    return res.json({ document: { id: doc.id, number: doc.number, status: doc.secretariat_status } });
  } catch (error) {
    return res.status(500).json({ error: "Failed to format document" });
  }
});

app.patch("/secretariat/documents/:id/send-to-assistant", authRequired, requireRole(["ADMIN", "SECRETARIAT"]), async (req, res) => {
  try {
    const { note } = req.body || {};
    const result = await query(
      `UPDATE reception_documents
       SET secretariat_status = 'ENVOYE_ASSISTANTE',
           secretariat_sent_at = NOW(),
           assistant_status = U&'\\00C0 traiter',
           observations = CASE WHEN $2 IS NOT NULL THEN COALESCE(observations || E'\n', '') || '[Secrétariat] ' || $2 ELSE observations END
       WHERE id = $1
         AND secretariat_status = 'FORMATE'
       RETURNING *`,
      [req.params.id, typeof note === "string" && note.trim() ? note.trim() : null]
    );
    const doc = result.rows[0];
    if (!doc) return res.status(404).json({ error: "Document not found or not formatted" });
    return res.json({ document: { id: doc.id, number: doc.number, status: doc.secretariat_status } });
  } catch (error) {
    return res.status(500).json({ error: "Failed to send document to assistant" });
  }
});

// ── DOCUMENTS (General) ──────────────────────────────────────────────

app.get("/documents/search", authRequired, async (req, res) => {
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
        d.confidentiality,
        d.document_type,
        d.assistant_status,
        d.assistant_priority,
        d.chief_decision,
        d.chief_assigned_to_type,
        d.chief_assigned_to_value,
        d.chief_priority,
        d.pilier_status,
        d.coordinator_status,
        d.secretariat_status,
        d.created_at,
        d.delivered_at,
        d.chief_decided_at,
        d.chief_sla_days
      FROM reception_documents d
      WHERE d.number ILIKE $1
         OR d.subject ILIKE $1
         OR d.sender ILIKE $1
         OR d.category ILIKE $1
         OR d.status ILIKE $1
         OR d.chief_assigned_to_value ILIKE $1
         OR d.chief_decision ILIKE $1
         OR d.confidentiality ILIKE $1
      ORDER BY d.created_at DESC
      LIMIT $2
      `,
      [likeQuery, limit]
    );

    const results = result.rows.map((row) => {
      const currentHolder = row.chief_assigned_to_value || row.sender;
      const holderRole = row.chief_assigned_to_type || "Expéditeur";
      const lastStatus = row.coordinator_status || row.pilier_status || row.secretariat_status || row.assistant_status || row.status;
      const priority = row.chief_priority || row.assistant_priority || "Normale";
      let isLate = false;
      if (row.chief_decided_at && row.chief_sla_days) {
        const deadline = new Date(row.chief_decided_at);
        deadline.setDate(deadline.getDate() + row.chief_sla_days);
        isLate = deadline < new Date() && !["Traité", "Clôturé", "Validé"].includes(lastStatus);
      }

      return {
        id: row.id,
        number: row.number,
        subject: row.subject,
        status: lastStatus,
        sender: row.sender,
        category: row.category,
        documentType: row.document_type,
        confidentiality: row.confidentiality,
        priority,
        currentHolder,
        holderRole,
        isLate,
        createdAt: row.created_at,
        deliveredAt: row.delivered_at
      };
    });

    return res.json({ results });
  } catch (error) {
    return res.status(500).json({ error: "Failed to search documents" });
  }
});

app.get("/documents", authRequired, async (req, res) => {
  try {
    const limit = Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 50, 1), 200);
    const offset = Math.max(Number.parseInt(req.query.offset, 10) || 0, 0);
    const status = typeof req.query.status === "string" ? req.query.status.trim() : "";
    const priority = typeof req.query.priority === "string" ? req.query.priority.trim() : "";
    const category = typeof req.query.category === "string" ? req.query.category.trim() : "";
    const late = req.query.late;

    const conditions = [];
    const params = [];
    let paramIndex = 1;

    if (status) {
      conditions.push(`(d.status = $${paramIndex} OR d.assistant_status = $${paramIndex} OR d.pilier_status = $${paramIndex} OR d.coordinator_status = $${paramIndex} OR d.secretariat_status = $${paramIndex})`);
      params.push(status);
      paramIndex++;
    }
    if (priority) {
      conditions.push(`(d.chief_priority = $${paramIndex} OR d.assistant_priority = $${paramIndex})`);
      params.push(priority);
      paramIndex++;
    }
    if (category) {
      conditions.push(`d.category = $${paramIndex}`);
      params.push(category);
      paramIndex++;
    }

    const whereClause = conditions.length > 0 ? "WHERE " + conditions.join(" AND ") : "";

    const result = await query(
      `
      SELECT
        d.id,
        d.number,
        d.subject,
        d.status,
        d.sender,
        d.category,
        d.confidentiality,
        d.document_type,
        d.assistant_status,
        d.assistant_priority,
        d.chief_decision,
        d.chief_assigned_to_type,
        d.chief_assigned_to_value,
        d.chief_priority,
        d.chief_sla_days,
        d.chief_decided_at,
        d.pilier_status,
        d.coordinator_status,
        d.secretariat_status,
        d.created_at,
        d.delivered_at
      FROM reception_documents d
      ${whereClause}
      ORDER BY d.created_at DESC
      LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
      `,
      [...params, limit, offset]
    );

    const countResult = await query(
      `SELECT COUNT(*) as total FROM reception_documents d ${whereClause}`,
      params
    );

    const documents = result.rows.map((row) => {
      const currentHolder = row.chief_assigned_to_value || row.sender;
      const holderRole = row.chief_assigned_to_type || "Expéditeur";
      const lastStatus = row.coordinator_status || row.pilier_status || row.secretariat_status || row.assistant_status || row.status;
      const prio = row.chief_priority || row.assistant_priority || "Normale";
      let isLate = false;
      let delayDays = 0;
      if (row.chief_decided_at && row.chief_sla_days) {
        const deadline = new Date(row.chief_decided_at);
        deadline.setDate(deadline.getDate() + row.chief_sla_days);
        const diff = Math.floor((Date.now() - deadline.getTime()) / 86400000);
        if (diff > 0 && !["Traité", "Clôturé", "Validé"].includes(lastStatus)) {
          isLate = true;
          delayDays = diff;
        }
      }

      return {
        id: row.id,
        number: row.number,
        subject: row.subject,
        documentType: row.document_type,
        status: lastStatus,
        category: row.category,
        priority: prio,
        currentHolder,
        holderRole,
        isLate,
        delayDays,
        createdAt: row.created_at
      };
    });

    const filtered = late === "true"
      ? documents.filter(d => d.isLate)
      : late === "false"
        ? documents.filter(d => !d.isLate)
        : documents;

    return res.json({
      documents: filtered,
      total: parseInt(countResult.rows[0].total),
      limit,
      offset
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to fetch documents" });
  }
});

app.post("/documents", authRequired, requireRole(["ADMIN", "CHEF_SG", "ASSISTANT_CHEF", "SECRETARIAT", "PILIER", "SERVICE_INTERNE"]), async (req, res) => {
  try {
    const { documentType, sender, subject, category, confidentiality, observations, priority, slaDays, description } = req.body || {};

    if (!sender || !subject || !category || !confidentiality) {
      return res.status(400).json({
        error: "sender, subject, category, and confidentiality are required"
      });
    }

    const allowedPriorities = ["Basse", "Normale", "Haute", "Urgente"];
    const normalizedPriority = typeof priority === "string" && allowedPriorities.includes(priority.trim())
      ? priority.trim()
      : "Normale";

    const receivedDate = new Date().toISOString().split("T")[0];
    const year = new Date().getFullYear();
    const docType = documentType || category || "NOTE_INTERNE";

    const sequenceResult = await query(
      `SELECT COALESCE(MAX(SUBSTRING(number FROM 12)::INT), 0) + 1 AS next_seq
       FROM reception_documents WHERE number LIKE $1`,
      [`COREF-${year}-%`]
    );

    const nextSequence = String(sequenceResult.rows[0].next_seq).padStart(4, "0");
    const number = `COREF-${year}-${nextSequence}`;

    const result = await query(
      `INSERT INTO reception_documents (
        number, document_type, received_date, sender, subject, category,
        confidentiality, observations, assistant_priority, created_by_user_id
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      RETURNING *`,
      [
        number, docType, receivedDate, sender, subject, category,
        confidentiality, observations || description || null,
        normalizedPriority, req.user.userId
      ]
    );

    return res.status(201).json({ document: sanitizeReceptionDocument(result.rows[0]) });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ error: "A document number conflict occurred. Please retry." });
    }
    return res.status(500).json({ error: "Failed to create document" });
  }
});

// ── RETARDS (Late documents) ─────────────────────────────────────────
app.get("/retards", authRequired, requireRole(["ADMIN", "CHEF_SG", "ASSISTANT_CHEF", "AUDITEUR"]), async (req, res) => {
  try {
    const lateResult = await query(`
      SELECT
        d.id, d.number, d.subject, d.sender,
        d.chief_assigned_to_value,
        d.chief_decided_at,
        d.chief_sla_days,
        COALESCE(d.chief_priority, d.assistant_priority, 'Normale') AS priority,
        d.assistant_status,
        d.pilier_status,
        d.coordinator_status,
        d.chief_decided_at + (d.chief_sla_days || ' days')::INTERVAL AS deadline,
        EXTRACT(DAY FROM NOW() - (d.chief_decided_at + (d.chief_sla_days || ' days')::INTERVAL))::INT AS delay_days
      FROM reception_documents d
      WHERE d.chief_decided_at IS NOT NULL
        AND d.chief_sla_days IS NOT NULL
        AND d.chief_decided_at + (d.chief_sla_days || ' days')::INTERVAL < NOW()
        AND d.assistant_status NOT IN ('Traité', 'Clôturé')
      ORDER BY delay_days DESC
    `);

    const documents = lateResult.rows.map(doc => ({
      id: doc.id,
      number: doc.number,
      subject: doc.subject,
      owner: doc.chief_assigned_to_value || doc.sender || '—',
      dueDate: doc.deadline ? new Date(doc.deadline).toLocaleDateString('fr-FR', { day: '2-digit', month: 'short', year: 'numeric' }) : '—',
      delayDays: doc.delay_days || 0,
      priority: doc.priority,
      status: doc.coordinator_status === 'VALIDE' ? 'Validé'
        : doc.pilier_status === 'EN_TRAITEMENT' ? 'En traitement'
        : doc.assistant_status || 'En retard'
    }));

    const totalLate = documents.length;
    const avgDelay = totalLate > 0 ? Math.round(documents.reduce((s, d) => s + d.delayDays, 0) / totalLate) : 0;

    // Top holders
    const holderMap = {};
    for (const doc of documents) {
      if (!holderMap[doc.owner]) holderMap[doc.owner] = { count: 0, totalDelay: 0 };
      holderMap[doc.owner].count++;
      holderMap[doc.owner].totalDelay += doc.delayDays;
    }
    const topHolders = Object.entries(holderMap)
      .map(([name, data]) => ({ name, count: data.count, averageDelay: Math.round(data.totalDelay / data.count) }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5);

    const maxHolder = topHolders[0] || null;

    return res.json({
      cards: {
        totalLate,
        avgDelay,
        maxHolderName: maxHolder ? maxHolder.name : '—',
        maxHolderCount: maxHolder ? maxHolder.count : 0
      },
      topHolders,
      documents
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to fetch late documents" });
  }
});

// ── RELANCES (Follow-ups) ────────────────────────────────────────────
app.get("/relances", authRequired, requireRole(["ADMIN", "CHEF_SG", "ASSISTANT_CHEF"]), async (req, res) => {
  try {
    // Documents approaching deadline (within 2 days) or past deadline
    const result = await query(`
      SELECT
        d.id, d.number, d.subject, d.sender,
        d.chief_assigned_to_value,
        d.chief_decided_at,
        d.chief_sla_days,
        COALESCE(d.chief_priority, d.assistant_priority, 'Normale') AS priority,
        d.assistant_status,
        d.chief_decided_at + (d.chief_sla_days || ' days')::INTERVAL AS deadline,
        EXTRACT(DAY FROM (d.chief_decided_at + (d.chief_sla_days || ' days')::INTERVAL) - NOW())::INT AS days_remaining
      FROM reception_documents d
      WHERE d.chief_decided_at IS NOT NULL
        AND d.chief_sla_days IS NOT NULL
        AND d.assistant_status NOT IN ('Traité', 'Clôturé')
      ORDER BY
        CASE WHEN d.chief_decided_at + (d.chief_sla_days || ' days')::INTERVAL < NOW() THEN 0 ELSE 1 END,
        (d.chief_decided_at + (d.chief_sla_days || ' days')::INTERVAL) ASC
    `);

    const documents = result.rows.map(doc => {
      const daysRemaining = doc.days_remaining || 0;
      let urgency = 'normal';
      if (daysRemaining < 0) urgency = 'overdue';
      else if (daysRemaining <= 2) urgency = 'critical';
      else if (daysRemaining <= 5) urgency = 'warning';

      return {
        id: doc.id,
        number: doc.number,
        subject: doc.subject,
        owner: doc.chief_assigned_to_value || doc.sender || '—',
        deadline: doc.deadline ? new Date(doc.deadline).toLocaleDateString('fr-FR', { day: '2-digit', month: 'short', year: 'numeric' }) : '—',
        daysRemaining,
        priority: doc.priority,
        status: doc.assistant_status || '—',
        urgency
      };
    });

    const overdue = documents.filter(d => d.urgency === 'overdue').length;
    const critical = documents.filter(d => d.urgency === 'critical').length;
    const warning = documents.filter(d => d.urgency === 'warning').length;

    return res.json({
      cards: { total: documents.length, overdue, critical, warning },
      documents
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to fetch follow-ups" });
  }
});

// ── AUDITEUR Dashboard ──────────────────────────────────────────────
app.get("/auditeur/dashboard", authRequired, requireRole(["ADMIN", "AUDITEUR"]), async (req, res) => {
  try {
    const statsResult = await query(`
      SELECT
        COUNT(*) AS total,
        COUNT(*) FILTER (WHERE assistant_status NOT IN ('Traité', 'Clôturé') AND chief_decided_at IS NOT NULL AND chief_sla_days IS NOT NULL AND chief_decided_at + (chief_sla_days || ' days')::INTERVAL < NOW()) AS late,
        COUNT(*) FILTER (WHERE chief_decided_at IS NOT NULL AND chief_sla_days IS NOT NULL AND chief_decided_at + (chief_sla_days || ' days')::INTERVAL >= NOW() AND assistant_status NOT IN ('Traité', 'Clôturé')) AS on_time,
        COUNT(*) FILTER (WHERE assistant_status IN ('Traité', 'Clôturé')) AS completed,
        COUNT(*) FILTER (WHERE COALESCE(chief_priority, assistant_priority) = 'Urgente') AS urgent,
        COUNT(*) FILTER (WHERE chief_decided_at IS NOT NULL) AS with_decision
      FROM reception_documents
    `);

    const stats = statsResult.rows[0];

    const recentResult = await query(`
      SELECT
        d.id, d.number, d.subject, d.sender,
        d.chief_assigned_to_value,
        d.assistant_status,
        d.chief_decision,
        COALESCE(d.chief_priority, d.assistant_priority, 'Normale') AS priority,
        d.chief_decided_at,
        d.chief_sla_days,
        d.pilier_status,
        d.coordinator_status,
        d.created_at,
        CASE
          WHEN d.chief_decided_at IS NOT NULL AND d.chief_sla_days IS NOT NULL
          THEN d.chief_decided_at + (d.chief_sla_days || ' days')::INTERVAL
          ELSE NULL
        END AS deadline
      FROM reception_documents d
      ORDER BY d.created_at DESC
      LIMIT 50
    `);

    const documents = recentResult.rows.map(doc => {
      const deadline = doc.deadline ? new Date(doc.deadline) : null;
      const isLate = deadline && deadline < new Date() && !['Traité', 'Clôturé'].includes(doc.assistant_status);
      return {
        id: doc.id,
        number: doc.number,
        subject: doc.subject,
        sender: doc.sender,
        owner: doc.chief_assigned_to_value || '—',
        status: doc.assistant_status,
        chiefDecision: doc.chief_decision || '—',
        priority: doc.priority,
        pilierStatus: doc.pilier_status || '—',
        coordinatorStatus: doc.coordinator_status || '—',
        deadline: deadline ? deadline.toISOString() : null,
        isLate: !!isLate,
        createdAt: doc.created_at
      };
    });

    return res.json({
      cards: {
        total: parseInt(stats.total),
        late: parseInt(stats.late),
        onTime: parseInt(stats.on_time),
        completed: parseInt(stats.completed),
        urgent: parseInt(stats.urgent),
        withDecision: parseInt(stats.with_decision)
      },
      documents
    });
  } catch (error) {
    return res.status(500).json({ error: "Failed to fetch auditeur dashboard" });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server listening on ${port}`);
});

/**
 * @openapi
 * /auth/register:
 *   post:
 *     summary: Register a user
 *     tags:
 *       - Auth
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - email
 *               - password
 *               - role
 *             properties:
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *               role:
 *                 type: string
 *               serviceId:
 *                 type: integer
 *     responses:
 *       201:
 *         description: User created
 *       400:
 *         description: Validation error
 */

/**
 * @openapi
 * /auth/login:
 *   post:
 *     summary: Login
 *     tags:
 *       - Auth
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Token issued
 *       401:
 *         description: Invalid credentials
 */