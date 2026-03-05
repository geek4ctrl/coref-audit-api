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
  ALTER COLUMN status SET DEFAULT U&'Document cr\00E9\00E9';

UPDATE reception_documents
SET status = U&'Document cr\00E9\00E9'
WHERE status LIKE 'Document cr%';

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
