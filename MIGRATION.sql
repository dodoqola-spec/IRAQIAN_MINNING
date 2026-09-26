-- Use this only if you already created the older IRAQIAN MINNING PRO database.
ALTER TABLE subscriptions ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
DO $$ BEGIN
  ALTER TABLE deposits DROP CONSTRAINT IF EXISTS deposits_status_check;
  ALTER TABLE deposits ADD CONSTRAINT deposits_status_check CHECK(status IN('pending','approved','rejected'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN
  ALTER TABLE withdrawals DROP CONSTRAINT IF EXISTS withdrawals_status_check;
  ALTER TABLE withdrawals ADD CONSTRAINT withdrawals_status_check CHECK(status IN('pending','paid','rejected'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
CREATE UNIQUE INDEX IF NOT EXISTS withdrawals_tx_hash_unique ON withdrawals(tx_hash) WHERE tx_hash IS NOT NULL;
