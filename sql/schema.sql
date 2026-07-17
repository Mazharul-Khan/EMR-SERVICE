--
-- PostgreSQL database dump
--

\restrict vWhqAiLEqeuNXJoBjSP9qFxMKrTldGQobTLydsD5WF9ZaVafHJHvEhr6C1cLVU6

-- Dumped from database version 18.3
-- Dumped by pg_dump version 18.3

-- Started on 2026-07-09 22:41:42

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- TOC entry 2 (class 3079 OID 32777)
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- TOC entry 5089 (class 0 OID 0)
-- Dependencies: 2
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- TOC entry 266 (class 1255 OID 32774)
-- Name: login_user(character varying, character varying); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.login_user(p_user_name character varying, p_password character varying) RETURNS TABLE(user_id uuid, user_name character varying, email character varying, is_active boolean, role_name character varying)
    LANGUAGE plpgsql
    AS $$
BEGIN
    ------------------------------------------------------------------
    -- Validate required inputs
    ------------------------------------------------------------------
    IF trim(coalesce(p_user_name, '')) = '' THEN
        RAISE EXCEPTION 'Username is required';
    END IF;

    IF trim(coalesce(p_password, '')) = '' THEN
        RAISE EXCEPTION 'Password is required';
    END IF;

    ------------------------------------------------------------------
    -- Verify username, password and active account
    ------------------------------------------------------------------
    RETURN QUERY
    SELECT
        u.user_id,
        u.user_name,
        u.email,
        u.is_active,
        r.role_name
    FROM users u
    INNER JOIN user_roles ur
        ON ur.user_id = u.user_id
    INNER JOIN roles r
        ON r.role_id = ur.role_id
    WHERE u.user_name = p_user_name
      AND u.password_hash = crypt(p_password, u.password_hash)
      AND u.is_active = TRUE;

    ------------------------------------------------------------------
    -- If no rows were returned, determine the reason
    ------------------------------------------------------------------
    IF NOT FOUND THEN

        -- Username doesn't exist
        IF NOT EXISTS (
            SELECT 1
            FROM users
            WHERE user_name = p_user_name
        ) THEN
            RAISE EXCEPTION 'Invalid username';

        END IF;

        -- Account exists but is inactive
        IF EXISTS (
            SELECT 1
            FROM users
            WHERE user_name = p_user_name
              AND is_active = FALSE
        ) THEN
            RAISE EXCEPTION 'User account is inactive';

        END IF;

        -- Username exists, therefore password is incorrect
        RAISE EXCEPTION 'Invalid password';

    END IF;

EXCEPTION

    ------------------------------------------------------------------
    -- Unexpected error
    ------------------------------------------------------------------
    WHEN OTHERS THEN
        RAISE;

END;
$$;


ALTER FUNCTION public.login_user(p_user_name character varying, p_password character varying) OWNER TO postgres;

--
-- TOC entry 276 (class 1255 OID 32775)
-- Name: save_auth_token(uuid, text); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.save_auth_token(p_user_id uuid, p_token text) RETURNS TABLE(token_id uuid, user_id uuid, token text, expires_at timestamp without time zone, is_active boolean)
    LANGUAGE plpgsql
    AS $$
#variable_conflict use_column  -- <--- ADD THIS LINE HERE
DECLARE
    v_token_id UUID;
BEGIN
    ------------------------------------------------------------------
    -- Validate required inputs
    ------------------------------------------------------------------
    IF p_user_id IS NULL THEN
        RAISE EXCEPTION 'User ID is required';
    END IF;

    IF trim(coalesce(p_token, '')) = '' THEN
        RAISE EXCEPTION 'Token is required';
    END IF;

    ------------------------------------------------------------------
    -- Verify user exists
    ------------------------------------------------------------------
    IF NOT EXISTS (
        SELECT 1
        FROM users u                 -- Added alias 'u' for extra safety
        WHERE u.user_id = p_user_id  -- Explicitly using u.user_id
    ) THEN
        RAISE EXCEPTION 'User does not exist';
    END IF;

    ------------------------------------------------------------------
    -- Revoke any currently active tokens
    ------------------------------------------------------------------
    UPDATE auth_tokens
    SET
        is_active = FALSE,
        revoked_at = CURRENT_TIMESTAMP
    WHERE auth_tokens.user_id = p_user_id -- Explicitly using table name prefix
      AND auth_tokens.is_active = TRUE;

    ------------------------------------------------------------------
    -- Save the new token
    ------------------------------------------------------------------
    INSERT INTO auth_tokens (
        token_id,
        user_id,
        token,
        expires_at,
        created_at,
        revoked_at,
        is_active
    )
    VALUES (
        gen_random_uuid(),
        p_user_id,
        p_token,
        CURRENT_TIMESTAMP + INTERVAL '30 days',
        CURRENT_TIMESTAMP,
        NULL,
        TRUE
    )
    RETURNING auth_tokens.token_id
    INTO v_token_id;

    ------------------------------------------------------------------
    -- Return the saved token
    ------------------------------------------------------------------
    RETURN QUERY
    SELECT
        at.token_id,
        at.user_id,
        at.token,
        at.expires_at,
        at.is_active
    FROM auth_tokens at
    WHERE at.token_id = v_token_id;

EXCEPTION

    ------------------------------------------------------------------
    -- Duplicate token
    ------------------------------------------------------------------
    WHEN unique_violation THEN
        RAISE EXCEPTION 'Token already exists';

    ------------------------------------------------------------------
    -- Foreign key violation
    ------------------------------------------------------------------
    WHEN foreign_key_violation THEN
        RAISE EXCEPTION 'Invalid user';

    ------------------------------------------------------------------
    -- Unexpected error
    ------------------------------------------------------------------
    WHEN OTHERS THEN
        RAISE;

END;
$$;


ALTER FUNCTION public.save_auth_token(p_user_id uuid, p_token text) OWNER TO postgres;

--
-- TOC entry 275 (class 1255 OID 32773)
-- Name: signup_user(character varying, character varying, character varying, character varying); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.signup_user(p_user_name character varying, p_email character varying, p_password character varying, p_role_name character varying) RETURNS TABLE(user_id uuid, user_name character varying, email character varying, is_active boolean, role_name character varying)
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_user_id UUID;
    v_password_hash VARCHAR(255);
    v_role_id INTEGER;
    v_constraint_name TEXT;
BEGIN
    ------------------------------------------------------------------
    -- Validate required inputs
    ------------------------------------------------------------------
    IF trim(coalesce(p_user_name, '')) = '' THEN
        RAISE EXCEPTION 'Username is required';
    END IF;

    IF trim(coalesce(p_email, '')) = '' THEN
        RAISE EXCEPTION 'Email is required';
    END IF;

    IF trim(coalesce(p_password, '')) = '' THEN
        RAISE EXCEPTION 'Password is required';
    END IF;

    IF trim(coalesce(p_role_name, '')) = '' THEN
        RAISE EXCEPTION 'Role is required';
    END IF;

    ------------------------------------------------------------------
    -- Validate role (Fixed: Added table alias 'r.')
    ------------------------------------------------------------------
    SELECT r.role_id
    INTO v_role_id
    FROM roles r
    WHERE r.role_name = p_role_name;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Role "%" does not exist.', p_role_name;
    END IF;

    ------------------------------------------------------------------
    -- Hash password
    ------------------------------------------------------------------
    v_password_hash := crypt(p_password, gen_salt('bf', 10));

    ------------------------------------------------------------------
    -- Create user
    ------------------------------------------------------------------
    INSERT INTO users (
        user_id,
        user_name,
        email,
        password_hash,
        is_active,
        created_at,
        updated_at
    )
    VALUES (
        gen_random_uuid(),
        p_user_name,
        p_email,
        v_password_hash,
        TRUE,
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
    )
    RETURNING users.user_id
    INTO v_user_id;

    ------------------------------------------------------------------
    -- Assign role
    ------------------------------------------------------------------
    INSERT INTO user_roles (
        user_id,
        role_id
    )
    VALUES (
        v_user_id,
        v_role_id
    );

    ------------------------------------------------------------------
    -- Return created user (Fixed: Using column positioning for safety)
    ------------------------------------------------------------------
    RETURN QUERY
    SELECT
        u.user_id,
        u.user_name,
        u.email,
        u.is_active,
        r.role_name
    FROM users u
    JOIN user_roles ur ON ur.user_id = u.user_id
    JOIN roles r ON r.role_id = ur.role_id
    WHERE u.user_id = v_user_id;

EXCEPTION
    ------------------------------------------------------------------
    -- Handle duplicate username/email
    ------------------------------------------------------------------
    WHEN unique_violation THEN

        GET STACKED DIAGNOSTICS
            v_constraint_name = CONSTRAINT_NAME;

        IF v_constraint_name = 'users_user_name_key' THEN
            RAISE EXCEPTION 'Username already exists';

        ELSIF v_constraint_name = 'users_email_key' THEN
            RAISE EXCEPTION 'Email already exists';

        ELSE
            RAISE;
        END IF;

    ------------------------------------------------------------------
    -- Handle foreign key violations
    ------------------------------------------------------------------
    WHEN foreign_key_violation THEN
        RAISE EXCEPTION 'Invalid role assignment';

END;
$$;


ALTER FUNCTION public.signup_user(p_user_name character varying, p_email character varying, p_password character varying, p_role_name character varying) OWNER TO postgres;

--
-- TOC entry 274 (class 1255 OID 32776)
-- Name: validate_token(text); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.validate_token(p_token text) RETURNS TABLE(user_id uuid, user_name character varying, email character varying, is_active boolean, role_name character varying, token_expires_at timestamp without time zone)
    LANGUAGE plpgsql
    AS $$
BEGIN
    ------------------------------------------------------------------
    -- Validate required input
    ------------------------------------------------------------------
    IF trim(coalesce(p_token, '')) = '' THEN
        RAISE EXCEPTION 'Token is required';
    END IF;

    ------------------------------------------------------------------
    -- Validate token and return user information
    ------------------------------------------------------------------
    RETURN QUERY
    SELECT
        u.user_id,
        u.user_name,
        u.email,
        u.is_active,
        r.role_name,
        at.expires_at
    FROM auth_tokens at
    INNER JOIN users u
        ON u.user_id = at.user_id
    INNER JOIN user_roles ur
        ON ur.user_id = u.user_id
    INNER JOIN roles r
        ON r.role_id = ur.role_id
    WHERE at.token = p_token
      AND at.is_active = TRUE
      AND at.revoked_at IS NULL
      AND at.expires_at > CURRENT_TIMESTAMP
      AND u.is_active = TRUE;

    ------------------------------------------------------------------
    -- Determine why validation failed
    ------------------------------------------------------------------
    IF NOT FOUND THEN

        -- Token doesn't exist
        IF NOT EXISTS (
            SELECT 1
            FROM auth_tokens
            WHERE token = p_token
        ) THEN
            RAISE EXCEPTION 'Invalid token';
        END IF;

        -- Token has been revoked
        IF EXISTS (
            SELECT 1
            FROM auth_tokens
            WHERE token = p_token
              AND revoked_at IS NOT NULL
        ) THEN
            RAISE EXCEPTION 'Token has been revoked';
        END IF;

        -- Token is inactive
        IF EXISTS (
            SELECT 1
            FROM auth_tokens
            WHERE token = p_token
              AND is_active = FALSE
        ) THEN
            RAISE EXCEPTION 'Token is inactive';
        END IF;

        -- Token has expired
        IF EXISTS (
            SELECT 1
            FROM auth_tokens
            WHERE token = p_token
              AND expires_at <= CURRENT_TIMESTAMP
        ) THEN
            RAISE EXCEPTION 'Token has expired';
        END IF;

        -- User account is inactive
        IF EXISTS (
            SELECT 1
            FROM auth_tokens at
            INNER JOIN users u
                ON u.user_id = at.user_id
            WHERE at.token = p_token
              AND u.is_active = FALSE
        ) THEN
            RAISE EXCEPTION 'User account is inactive';
        END IF;

        RAISE EXCEPTION 'Token validation failed';

    END IF;

EXCEPTION

    ------------------------------------------------------------------
    -- Unexpected error
    ------------------------------------------------------------------
    WHEN OTHERS THEN
        RAISE;

END;
$$;


ALTER FUNCTION public.validate_token(p_token text) OWNER TO postgres;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- TOC entry 224 (class 1259 OID 16433)
-- Name: auth_tokens; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.auth_tokens (
    token_id uuid DEFAULT gen_random_uuid() CONSTRAINT refresh_tokens_token_id_not_null NOT NULL,
    user_id uuid,
    token text CONSTRAINT refresh_tokens_token_not_null NOT NULL,
    expires_at timestamp without time zone CONSTRAINT refresh_tokens_expires_at_not_null NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    revoked_at timestamp without time zone,
    is_active boolean DEFAULT true CONSTRAINT refresh_tokens_is_active_not_null NOT NULL
);


ALTER TABLE public.auth_tokens OWNER TO postgres;

--
-- TOC entry 222 (class 1259 OID 16406)
-- Name: roles; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.roles (
    role_id integer NOT NULL,
    role_name character varying(50) NOT NULL
);


ALTER TABLE public.roles OWNER TO postgres;

--
-- TOC entry 221 (class 1259 OID 16405)
-- Name: roles_role_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.roles_role_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.roles_role_id_seq OWNER TO postgres;

--
-- TOC entry 5090 (class 0 OID 0)
-- Dependencies: 221
-- Name: roles_role_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.roles_role_id_seq OWNED BY public.roles.role_id;


--
-- TOC entry 223 (class 1259 OID 16416)
-- Name: user_roles; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.user_roles (
    user_id uuid NOT NULL,
    role_id integer NOT NULL
);


ALTER TABLE public.user_roles OWNER TO postgres;

--
-- TOC entry 220 (class 1259 OID 16389)
-- Name: users; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.users (
    user_id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_name character varying(255) CONSTRAINT users_email_not_null NOT NULL,
    password_hash character varying(255) NOT NULL,
    is_active boolean DEFAULT true,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    email character varying(255) CONSTRAINT users_email_not_null1 NOT NULL
);


ALTER TABLE public.users OWNER TO postgres;

--
-- TOC entry 4914 (class 2604 OID 16409)
-- Name: roles role_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.roles ALTER COLUMN role_id SET DEFAULT nextval('public.roles_role_id_seq'::regclass);


--
-- TOC entry 4931 (class 2606 OID 16444)
-- Name: auth_tokens auth_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.auth_tokens
    ADD CONSTRAINT auth_tokens_pkey PRIMARY KEY (token_id);


--
-- TOC entry 4933 (class 2606 OID 16446)
-- Name: auth_tokens auth_tokens_token_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.auth_tokens
    ADD CONSTRAINT auth_tokens_token_key UNIQUE (token);


--
-- TOC entry 4925 (class 2606 OID 16413)
-- Name: roles roles_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (role_id);


--
-- TOC entry 4927 (class 2606 OID 16415)
-- Name: roles roles_role_name_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_role_name_key UNIQUE (role_name);


--
-- TOC entry 4929 (class 2606 OID 16422)
-- Name: user_roles user_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_pkey PRIMARY KEY (user_id, role_id);


--
-- TOC entry 4919 (class 2606 OID 32772)
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- TOC entry 4921 (class 2606 OID 16402)
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (user_id);


--
-- TOC entry 4923 (class 2606 OID 16404)
-- Name: users users_user_name_key; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_user_name_key UNIQUE (user_name);


--
-- TOC entry 4936 (class 2606 OID 16447)
-- Name: auth_tokens auth_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.auth_tokens
    ADD CONSTRAINT auth_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- TOC entry 4934 (class 2606 OID 16428)
-- Name: user_roles user_roles_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(role_id) ON DELETE CASCADE;


--
-- TOC entry 4935 (class 2606 OID 16423)
-- Name: user_roles user_roles_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


-- Completed on 2026-07-09 22:41:43

--
-- PostgreSQL database dump complete
--

\unrestrict vWhqAiLEqeuNXJoBjSP9qFxMKrTldGQobTLydsD5WF9ZaVafHJHvEhr6C1cLVU6

