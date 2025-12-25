-- Seed data for ZT-NMS
-- Default admin user: admin / admin

-- Create admin user identity
-- Password hash is bcrypt of 'admin'
INSERT INTO identities (id, type, attributes, public_key, status) VALUES (
    '00000000-0000-0000-0000-000000000002',
    'operator',
    '{
        "username": "admin",
        "email": "admin@zt-nms.local",
        "display_name": "Administrator",
        "role": "admin",
        "password_hash": "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
    }',
    E'\\x0000000000000000000000000000000000000000000000000000000000000001',
    'active'
) ON CONFLICT (id) DO NOTHING;

-- Create operators table for login credentials
CREATE TABLE IF NOT EXISTS operators (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    role VARCHAR(50) NOT NULL DEFAULT 'operator',
    last_login TIMESTAMPTZ,
    login_count INTEGER DEFAULT 0,
    failed_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_operators_username ON operators(username);
CREATE INDEX IF NOT EXISTS idx_operators_identity ON operators(identity_id);

-- Insert admin operator
-- Password: admin (bcrypt hash generated from 'admin')
INSERT INTO operators (id, identity_id, username, password_hash, email, role) VALUES (
    '00000000-0000-0000-0000-000000000002',
    '00000000-0000-0000-0000-000000000002',
    'admin',
    '$2a$10$2ie19beJQwnQGb1a.OmKz.9uJgHjWNeejaL06VgdJvOmI6n9iu0Ym',
    'admin@zt-nms.local',
    'admin'
) ON CONFLICT (id) DO NOTHING;

-- Create refresh tokens table
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    operator_id UUID NOT NULL REFERENCES operators(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked BOOLEAN DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_operator ON refresh_tokens(operator_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);
