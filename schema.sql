CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE TABLE IF NOT EXISTS users(
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'user' CHECK(role IN('user','admin')), balance NUMERIC(30,6) NOT NULL DEFAULT 0,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS sessions(
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(), user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 token_hash TEXT UNIQUE NOT NULL, expires_at TIMESTAMPTZ NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS plans(
 id SERIAL PRIMARY KEY,name TEXT NOT NULL,price NUMERIC(30,6) NOT NULL,duration_days INT NOT NULL DEFAULT 30,
 active BOOLEAN NOT NULL DEFAULT true
);
CREATE TABLE IF NOT EXISTS subscriptions(
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),user_id UUID NOT NULL REFERENCES users(id),plan_id INT NOT NULL REFERENCES plans(id),
 amount NUMERIC(30,6) NOT NULL,starts_at TIMESTAMPTZ NOT NULL DEFAULT now(),ends_at TIMESTAMPTZ NOT NULL,
 status TEXT NOT NULL DEFAULT 'active',created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS deposits(
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),user_id UUID NOT NULL REFERENCES users(id),network TEXT NOT NULL CHECK(network IN('polygon','bsc')),
 tx_hash TEXT NOT NULL,amount NUMERIC(30,6),status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN('pending','approved','rejected')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT now(),verified_at TIMESTAMPTZ,UNIQUE(network,tx_hash)
);
CREATE TABLE IF NOT EXISTS withdrawals(
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),user_id UUID NOT NULL REFERENCES users(id),network TEXT NOT NULL CHECK(network IN('polygon','bsc')),
 address TEXT NOT NULL,amount NUMERIC(30,6) NOT NULL,status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN('pending','paid','rejected')),
 tx_hash TEXT UNIQUE,created_at TIMESTAMPTZ NOT NULL DEFAULT now(),paid_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS audit_logs(
 id BIGSERIAL PRIMARY KEY,user_id UUID,action TEXT NOT NULL,metadata JSONB,created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO plans(name,price,duration_days)
SELECT * FROM (VALUES
('الاشتراك الأساسي',5,30),('الاشتراك البرونزي',10,30),('الاشتراك الفضي',20,30),('الاشتراك المتقدم',50,30),
('الاشتراك الاحترافي',100,30),('اشتراك VIP',200,30),('اشتراك Premium',300,30),('اشتراك Business',400,30),('اشتراك Enterprise',500,30)
)v(name,price,duration_days) WHERE NOT EXISTS(SELECT 1 FROM plans);
