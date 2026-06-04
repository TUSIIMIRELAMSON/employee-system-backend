import psycopg2
import psycopg2.extras
import os
from dotenv import load_dotenv

load_dotenv()

def get_connection():
    """Return a new database connection."""
    return psycopg2.connect(os.environ["DATABASE_URL"])

def init_db():
    """Create all tables if they don't exist yet."""
    conn = get_connection()
    cur  = conn.cursor()

    cur.execute("""

        -- ── Companies ──────────────────────────────────
        CREATE TABLE IF NOT EXISTS companies (
            id                   SERIAL PRIMARY KEY,
            registration_number  VARCHAR(50) UNIQUE NOT NULL,
            company_name         VARCHAR(150) NOT NULL,
            business_type        VARCHAR(100),
            business_address     TEXT,
            owner_name           VARCHAR(100),
            owner_email          VARCHAR(150),
            owner_phone          VARCHAR(30),
            business_activities  TEXT,
            secret_code          VARCHAR(255) NOT NULL,
            created_at           TIMESTAMPTZ DEFAULT NOW()
        );

        -- ── Users ───────────────────────────────────────
        CREATE TABLE IF NOT EXISTS users (
            id          SERIAL PRIMARY KEY,
            company_id  INT NOT NULL REFERENCES companies(id),
            name        VARCHAR(100) NOT NULL,
            email       VARCHAR(150) NOT NULL,
            password    VARCHAR(255) NOT NULL,
            role        VARCHAR(20) DEFAULT 'user',
            created_at  TIMESTAMPTZ DEFAULT NOW(),
            UNIQUE (company_id, email)
        );

        -- ── Employees ───────────────────────────────────
        CREATE TABLE IF NOT EXISTS employees_table (
            company_id  INT NOT NULL REFERENCES companies(id),
            emp_no      INT NOT NULL,
            birth_date  DATE NOT NULL,
            first_name  VARCHAR(50) NOT NULL,
            last_name   VARCHAR(50) NOT NULL,
            gender      CHAR(1) NOT NULL CHECK (gender IN ('M','F')),
            hire_date   DATE NOT NULL,
            PRIMARY KEY (company_id, emp_no)
        );

        -- ── Departments ─────────────────────────────────
        CREATE TABLE IF NOT EXISTS departments (
            company_id  INT NOT NULL REFERENCES companies(id),
            dept_no     VARCHAR(10) NOT NULL,
            dept_name   VARCHAR(100) NOT NULL,
            PRIMARY KEY (company_id, dept_no)
        );

        -- ── Dept Manager ────────────────────────────────
        CREATE TABLE IF NOT EXISTS dept_manager (
            company_id  INT NOT NULL REFERENCES companies(id),
            emp_no      INT NOT NULL,
            dept_no     VARCHAR(10) NOT NULL,
            from_date   DATE NOT NULL,
            to_date     DATE NOT NULL,
            PRIMARY KEY (company_id, emp_no, dept_no)
        );

        -- ── Dept Employees ──────────────────────────────
        CREATE TABLE IF NOT EXISTS dept_employees (
            company_id  INT NOT NULL REFERENCES companies(id),
            emp_no      INT NOT NULL,
            dept_no     VARCHAR(10) NOT NULL,
            from_date   DATE NOT NULL,
            to_date     DATE NOT NULL,
            PRIMARY KEY (company_id, emp_no, dept_no)
        );

        -- ── Salaries ────────────────────────────────────
        CREATE TABLE IF NOT EXISTS salaries (
            company_id  INT NOT NULL REFERENCES companies(id),
            emp_no      INT NOT NULL,
            salary      INT NOT NULL,
            from_date   DATE NOT NULL,
            to_date     DATE NOT NULL,
            PRIMARY KEY (company_id, emp_no, from_date)
        );

        -- ── Messages ────────────────────────────────────
        CREATE TABLE IF NOT EXISTS messages (
            id          SERIAL PRIMARY KEY,
            company_id  INT NOT NULL REFERENCES companies(id),
            user_name   VARCHAR(100) NOT NULL,
            user_email  VARCHAR(150) NOT NULL,
            content     TEXT NOT NULL,
            created_at  TIMESTAMPTZ DEFAULT NOW()
        );

    """)

    conn.commit()
    cur.close()
    conn.close()
    print("✅ Database tables ready.")