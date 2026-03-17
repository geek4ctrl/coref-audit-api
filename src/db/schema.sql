CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL,
  service_id INTEGER,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS users_role_idx ON users(role);
CREATE INDEX IF NOT EXISTS users_service_idx ON users(service_id);

CREATE TABLE IF NOT EXISTS reception_documents (
  id SERIAL PRIMARY KEY,
  number TEXT NOT NULL UNIQUE,
  document_type TEXT NOT NULL,
  received_date DATE NOT NULL,
  sender TEXT NOT NULL,
  subject TEXT NOT NULL,
  category TEXT NOT NULL,
  confidentiality TEXT NOT NULL,
  observations TEXT,
  status TEXT NOT NULL DEFAULT U&'Document cr\00E9\00E9',
  created_by_user_id INTEGER REFERENCES users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS reception_documents_created_at_idx
  ON reception_documents(created_at DESC);

CREATE INDEX IF NOT EXISTS reception_documents_received_date_idx
  ON reception_documents(received_date DESC);

ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS delivered_at TIMESTAMPTZ;

ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS assistant_status TEXT NOT NULL DEFAULT U&'\00C0 traiter';

ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS assistant_priority TEXT NOT NULL DEFAULT 'Normale';

ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS assistant_note TEXT;

ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS assistant_sent_to_chief_at TIMESTAMPTZ;

ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS assistant_treated_at TIMESTAMPTZ;

ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS chief_decision TEXT;

ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS chief_assigned_to_type TEXT;

ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS chief_assigned_to_value TEXT;

ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS chief_priority TEXT;

ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS chief_sla_days INTEGER;

ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS chief_instruction TEXT;

ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS chief_decided_at TIMESTAMPTZ;

ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS chief_decided_by_user_id INTEGER REFERENCES users(id);

ALTER TABLE reception_documents
  ALTER COLUMN status SET DEFAULT U&'Document cr\00E9\00E9';

UPDATE reception_documents
SET status = U&'Document cr\00E9\00E9'
WHERE status LIKE 'Document cr%';

UPDATE reception_documents
SET assistant_status = U&'\00C0 traiter'
WHERE assistant_status IS NULL;

UPDATE reception_documents
SET assistant_priority = 'Normale'
WHERE assistant_priority IS NULL;

CREATE INDEX IF NOT EXISTS reception_documents_assistant_status_idx
  ON reception_documents(assistant_status);

CREATE INDEX IF NOT EXISTS reception_documents_assistant_priority_idx
  ON reception_documents(assistant_priority);

CREATE INDEX IF NOT EXISTS reception_documents_chief_decision_idx
  ON reception_documents(chief_decision);

CREATE TABLE IF NOT EXISTS reception_bordereaux (
  id SERIAL PRIMARY KEY,
  document_id INTEGER NOT NULL UNIQUE REFERENCES reception_documents(id) ON DELETE CASCADE,
  number TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT U&'Non sign\00E9',
  generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  signed_at TIMESTAMPTZ
);

ALTER TABLE reception_bordereaux
  ALTER COLUMN status SET DEFAULT U&'Non sign\00E9';

UPDATE reception_bordereaux
SET status = U&'Non sign\00E9'
WHERE status LIKE 'Non sign%';

CREATE INDEX IF NOT EXISTS reception_bordereaux_generated_at_idx
  ON reception_bordereaux(generated_at DESC);

CREATE INDEX IF NOT EXISTS reception_bordereaux_status_idx
  ON reception_bordereaux(status);

CREATE TABLE IF NOT EXISTS messages (
  id SERIAL PRIMARY KEY,
  sender_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  subject TEXT NOT NULL,
  content TEXT NOT NULL,
  read_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS messages_recipient_created_at_idx
  ON messages(recipient_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS messages_sender_created_at_idx
  ON messages(sender_user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS message_attachments (
  id SERIAL PRIMARY KEY,
  message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
  file_name TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  storage_path TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS message_attachments_message_id_idx
  ON message_attachments(message_id);

CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS users_set_updated_at ON users;
CREATE TRIGGER users_set_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- Pilier workflow columns
ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS pilier_status TEXT;

ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS pilier_acknowledged_at TIMESTAMPTZ;

ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS pilier_started_at TIMESTAMPTZ;

ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS pilier_finalized_at TIMESTAMPTZ;

ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS pilier_sent_to_coordinator_at TIMESTAMPTZ;

ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS pilier_note TEXT;

ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS pilier_user_id INTEGER REFERENCES users(id);

-- Coordinator workflow columns
ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS coordinator_status TEXT;

ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS coordinator_validated_at TIMESTAMPTZ;

ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS coordinator_rejected_at TIMESTAMPTZ;

ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS coordinator_comment TEXT;

ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS coordinator_user_id INTEGER REFERENCES users(id);

CREATE INDEX IF NOT EXISTS reception_documents_pilier_status_idx
  ON reception_documents(pilier_status);

CREATE INDEX IF NOT EXISTS reception_documents_coordinator_status_idx
  ON reception_documents(coordinator_status);

CREATE INDEX IF NOT EXISTS reception_documents_pilier_user_idx
  ON reception_documents(pilier_user_id);

-- Secrétariat workflow columns
ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS secretariat_status TEXT;

ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS secretariat_formatted_at TIMESTAMPTZ;

ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS secretariat_sent_at TIMESTAMPTZ;

ALTER TABLE reception_documents
  ADD COLUMN IF NOT EXISTS secretariat_user_id INTEGER REFERENCES users(id);

CREATE INDEX IF NOT EXISTS reception_documents_secretariat_status_idx
  ON reception_documents(secretariat_status);

-- Services table
CREATE TABLE IF NOT EXISTS services (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  code TEXT NOT NULL UNIQUE,
  description TEXT,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS services_code_idx ON services(code);

DROP TRIGGER IF EXISTS services_set_updated_at ON services;
CREATE TRIGGER services_set_updated_at
BEFORE UPDATE ON services
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- Piliers table
CREATE TABLE IF NOT EXISTS piliers (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  code TEXT NOT NULL UNIQUE,
  description TEXT,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS piliers_code_idx ON piliers(code);

DROP TRIGGER IF EXISTS piliers_set_updated_at ON piliers;
CREATE TRIGGER piliers_set_updated_at
BEFORE UPDATE ON piliers
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- Audit logs table
CREATE TABLE IF NOT EXISTS audit_logs (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id),
  user_email TEXT,
  user_role TEXT,
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT,
  details JSONB,
  ip_address TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS audit_logs_created_at_idx ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS audit_logs_user_id_idx ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS audit_logs_action_idx ON audit_logs(action);
CREATE INDEX IF NOT EXISTS audit_logs_entity_type_idx ON audit_logs(entity_type);

-- Seed services if empty
INSERT INTO services (name, code, description) VALUES
  ('Direction des Ressources Humaines', 'DRH', 'Gestion du personnel et des ressources humaines'),
  ('Direction du Budget', 'BUDGET', 'Préparation et suivi du budget'),
  ('Direction de la Comptabilité', 'COMPTA', 'Comptabilité générale et analytique'),
  ('Service du Protocole', 'PROTO', 'Protocole et relations publiques'),
  ('Service Logistique', 'LOG', 'Gestion de la logistique et des approvisionnements'),
  ('Service Juridique', 'JUR', 'Conseil juridique et contentieux'),
  ('Direction Informatique', 'INFO', 'Support technique et systèmes d''information'),
  ('Service Financier', 'FIN', 'Gestion financière et comptabilité'),
  ('Service Communication', 'COM', 'Communication interne et externe'),
  ('Service Maintenance', 'MAINT', 'Maintenance des bâtiments et équipements'),
  ('Service Courrier', 'COUR', 'Gestion du courrier et des envois'),
  ('Service Réception', 'RECEP', 'Réception et enregistrement des courriers entrants'),
  ('Service Nettoyage', 'NETT', 'Entretien et nettoyage des locaux'),
  ('Service Archive', 'ARCH', 'Archivage et conservation des documents'),
  ('Service Administratif', 'ADMIN', 'Administration générale et appui administratif'),
  ('Secrétariat', 'SEC', 'Secrétariat général et appui administratif')
ON CONFLICT (code) DO NOTHING;

-- Seed piliers if empty
INSERT INTO piliers (name, code, description) VALUES
  ('Comptabilité Publique', 'P01', 'Normalisation et fiabilisation des comptes publics'),
  ('Gestion de la Trésorerie', 'P02', 'Prévision et optimisation de la trésorerie'),
  ('Réformes Budgétaires', 'P03', 'Modernisation du cycle budgétaire'),
  ('Contrôle Interne', 'P04', 'Renforcement des dispositifs de contrôle'),
  ('Digitalisation', 'P05', 'Transformation numérique des processus'),
  ('Achat Public', 'P06', 'Amélioration des procédures de passation'),
  ('Performance', 'P07', 'Pilotage par résultats et indicateurs'),
  ('Gouvernance', 'P08', 'Transparence et redevabilité'),
  ('Audit Interne', 'P09', 'Renforcement des audits et conformité'),
  ('Partenariats', 'P10', 'Coordination avec les partenaires techniques'),
  ('Communication', 'P11', 'Diffusion des réformes et gestion du changement')
ON CONFLICT (code) DO NOTHING;
