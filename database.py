import psycopg2
import psycopg2.extras
import os
from dotenv import load_dotenv

load_dotenv()

def get_connection():
    """Return a new database connection."""
    url = os.environ["DATABASE_URL"]
    return psycopg2.connect(url, sslmode="require", connect_timeout=10)

def init_db():
    """Create all tables if they don't exist yet."""
    conn = get_connection()
    cur  = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id         SERIAL PRIMARY KEY,
            name       VARCHAR(100) NOT NULL,
            email      VARCHAR(150) UNIQUE NOT NULL,
            password   VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS employees_table (
            emp_no     INT PRIMARY KEY,
            birth_date DATE NOT NULL,
            first_name VARCHAR(50) NOT NULL,
            last_name  VARCHAR(50) NOT NULL,
            gender     CHAR(1) NOT NULL CHECK (gender IN ('M','F')),
            hire_date  DATE NOT NULL
        );

        CREATE TABLE IF NOT EXISTS departments (
            dept_no   VARCHAR(10) PRIMARY KEY,
            dept_name VARCHAR(100) NOT NULL
        );

        CREATE TABLE IF NOT EXISTS dept_manager (
            emp_no    INT NOT NULL,
            dept_no   VARCHAR(10) NOT NULL,
            from_date DATE NOT NULL,
            to_date   DATE NOT NULL,
            PRIMARY KEY (emp_no, dept_no)
        );

        CREATE TABLE IF NOT EXISTS dept_employees (
            emp_no    INT NOT NULL,
            dept_no   VARCHAR(10) NOT NULL,
            from_date DATE NOT NULL,
            to_date   DATE NOT NULL,
            PRIMARY KEY (emp_no, dept_no)
        );

        CREATE TABLE IF NOT EXISTS salaries (
            emp_no    INT NOT NULL,
            salary    INT NOT NULL,
            from_date DATE NOT NULL,
            to_date   DATE NOT NULL,
            PRIMARY KEY (emp_no, from_date)
        );
    """)

    conn.commit()
    cur.close()
    conn.close()
    print("✅ Database tables ready.")
