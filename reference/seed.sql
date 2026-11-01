-- Fictional sample data. Runs as client_loader on every bootstrap: no reset, no duplicates.
CREATE TABLE IF NOT EXISTS accounts (
  account_no integer PRIMARY KEY,
  name text NOT NULL,
  kind text NOT NULL
);
CREATE TABLE IF NOT EXISTS monthly_close (
  period date PRIMARY KEY,
  revenue numeric(12,2) NOT NULL,
  cost_of_sales numeric(12,2) NOT NULL,
  closed boolean NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS client_marker (
  id integer PRIMARY KEY,
  client_id text NOT NULL,
  marker text NOT NULL
);
INSERT INTO accounts VALUES
  (1000, 'Operating cash', 'asset'),
  (1200, 'Accounts receivable', 'asset'),
  (4000, 'Service revenue', 'income'),
  (5000, 'Materials', 'cost')
ON CONFLICT (account_no) DO NOTHING;
INSERT INTO monthly_close VALUES
  ('2026-08-01', 100000.00, 60000.00, true),
  ('2026-09-01', 110000.00, 64000.00, true)
ON CONFLICT (period) DO NOTHING;
INSERT INTO client_marker VALUES (1, %(client_id)s, %(marker)s)
ON CONFLICT (id) DO NOTHING;
