-- ============================================================
-- GasyTalk — Schema PostgreSQL (Neon)
-- Alefaso amin'ny SQL Editor-nao (Neon console) na amin'ny psql:
--   createdb gasytalk
--   psql -d gasytalk -f schema.sql
-- Morganna: CREATE ... IF NOT EXISTS => azo averina inènana azafady
-- ============================================================

-- ---------------- PROFILES ----------------
CREATE TABLE IF NOT EXISTS public.profiles (
  id        uuid NOT NULL PRIMARY KEY,
  email     text NOT NULL UNIQUE,
  password_hash text,
  first_name text,
  last_name text,
  level     text DEFAULT 'A1',
  language  text DEFAULT 'fr',
  status    text,
  last_seen timestamptz,
  avatar_url text,
  role      text DEFAULT 'user',
  is_online boolean DEFAULT false,
  is_premium boolean DEFAULT false,
  trial_started_at timestamptz,
  trial_expired boolean DEFAULT false,
  is_subscriber boolean DEFAULT false,
  subscription_end timestamptz,
  created_at timestamptz DEFAULT now()
);

-- ---------------- MESSAGES ----------------
CREATE TABLE IF NOT EXISTS public.messages (
  id         uuid NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
  sender_id  uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  receiver_id uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  content    text,
  voice_url  text,
  type       text NOT NULL DEFAULT 'text',
  created_at timestamptz DEFAULT now(),
  read       boolean DEFAULT false,
  seen_at    timestamptz,
  is_seen    boolean DEFAULT false,
  deleted_by uuid[] DEFAULT '{}'
);

-- ---------------- PAYMENTS (abonnement) ----------------
CREATE TABLE IF NOT EXISTS public.payments (
  id         uuid NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  amount     integer NOT NULL,
  reference  text NOT NULL,
  status     text NOT NULL DEFAULT 'pending',
  created_at timestamptz DEFAULT now()
);

-- ---------------- NOTIFICATIONS ----------------
CREATE TABLE IF NOT EXISTS public.notifications (
  id         uuid NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  message    text NOT NULL,
  read       boolean DEFAULT false,
  created_at timestamptz DEFAULT now()
);

-- ---------------- OTP CODES (verify email) ----------------
CREATE TABLE IF NOT EXISTS public.otp_codes (
  email      text NOT NULL PRIMARY KEY,
  code       text NOT NULL,
  purpose    text NOT NULL DEFAULT 'signup',
  expires_at timestamptz NOT NULL
);

-- ---------------- Indexes mampandeha ny chat ----------------
CREATE INDEX IF NOT EXISTS idx_messages_pair
  ON public.messages (sender_id, receiver_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_messages_read
  ON public.messages (receiver_id, read);

CREATE INDEX IF NOT EXISTS idx_payments_status
  ON public.payments (status);

CREATE INDEX IF NOT EXISTS idx_notifications_user
  ON public.notifications (user_id, read);

CREATE INDEX IF NOT EXISTS idx_profiles_online
  ON public.profiles (is_online);