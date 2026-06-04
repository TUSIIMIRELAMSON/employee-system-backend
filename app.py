from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)
import bcrypt
import os
import datetime
import psycopg2.extras
from dotenv import load_dotenv
from database import get_connection, init_db

load_dotenv()

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = os.environ.get("JWT_SECRET_KEY", "dev-secret-change-me")

CORS(app, origins="*")
jwt = JWTManager(app)


# ── Helpers ─────────────────────────────────

def format_dates(obj):
    if isinstance(obj, list):
        return [format_dates(i) for i in obj]
    if isinstance(obj, dict):
        return {k: format_dates(v) for k, v in obj.items()}
    if isinstance(obj, datetime.datetime):
        return obj.strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(obj, datetime.date):
        return obj.strftime("%Y-%m-%d")
    return obj

def ok(data=None, msg="success", code=200):
    return jsonify({"status": "ok", "message": msg, "data": format_dates(data)}), code

def err(msg, code=400):
    return jsonify({"status": "error", "message": msg}), code

def get_current_user():
    """Get current user with company_id from JWT identity."""
    identity = get_jwt_identity()
    conn = get_connection()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM users WHERE id = %s", (identity,))
    user = cur.fetchone()
    cur.close(); conn.close()
    return user


# ══════════════════════════════════════════════
#  COMPANY ROUTES
# ══════════════════════════════════════════════

@app.route("/api/company/register", methods=["POST"])
def register_company():
    b = request.get_json()
    required = ["registration_number", "company_name", "secret_code"]
    if not all(b.get(f) for f in required):
        return err("Registration number, company name and secret code are required.")

    hashed_secret = bcrypt.hashpw(
        b["secret_code"].encode(), bcrypt.gensalt()
    ).decode()

    conn = get_connection()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute("""
            INSERT INTO companies
              (registration_number, company_name, business_type, business_address,
               owner_name, owner_email, owner_phone, business_activities, secret_code)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            RETURNING id, registration_number, company_name
        """, (
            b["registration_number"], b["company_name"],
            b.get("business_type",""), b.get("business_address",""),
            b.get("owner_name",""), b.get("owner_email",""),
            b.get("owner_phone",""), b.get("business_activities",""),
            hashed_secret
        ))
        company = dict(cur.fetchone())
        conn.commit()
    except Exception as e:
        conn.rollback()
        return err("A company with this registration number already exists.")
    finally:
        cur.close(); conn.close()

    return ok(company, msg="Company registered successfully.", code=201)


@app.route("/api/company/verify", methods=["POST"])
def verify_company():
    """Verify registration number + secret code. Returns company info."""
    b = request.get_json()
    reg_no      = (b.get("registration_number") or "").strip()
    secret_code = (b.get("secret_code") or "")

    if not reg_no or not secret_code:
        return err("Registration number and secret code are required.")

    conn = get_connection()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM companies WHERE registration_number = %s", (reg_no,))
    company = cur.fetchone()
    cur.close(); conn.close()

    if not company:
        return err("No company found with that registration number.", 404)
    if not bcrypt.checkpw(secret_code.encode(), company["secret_code"].encode()):
        return err("Incorrect secret code.", 401)

    return ok({
        "id":                  company["id"],
        "company_name":        company["company_name"],
        "registration_number": company["registration_number"],
        "business_type":       company["business_type"],
        "owner_name":          company["owner_name"],
    })


# ══════════════════════════════════════════════
#  AUTH ROUTES
# ══════════════════════════════════════════════

@app.route("/api/signup", methods=["POST"])
def signup():
    b = request.get_json()
    name        = (b.get("name") or "").strip()
    email       = (b.get("email") or "").strip().lower()
    password    = (b.get("password") or "")
    company_id  = b.get("company_id")
    role        = b.get("role", "user")

    if not name or not email or not password or not company_id:
        return err("All fields including company ID are required.")
    if len(password) < 6:
        return err("Password must be at least 6 characters.")
    if role not in ["admin", "user"]:
        role = "user"

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    conn = get_connection()
    cur  = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (company_id, name, email, password, role) VALUES (%s,%s,%s,%s,%s)",
            (company_id, name, email, hashed, role)
        )
        conn.commit()
    except Exception:
        conn.rollback()
        return err("An account with this email already exists in your company.")
    finally:
        cur.close(); conn.close()

    return ok(msg="Account created successfully.", code=201)


@app.route("/api/signin", methods=["POST"])
def signin():
    b = request.get_json()
    email    = (b.get("email") or "").strip().lower()
    password = (b.get("password") or "")
    company_id = b.get("company_id")

    if not company_id:
        return err("Company ID is required.", 400)

    conn = get_connection()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(
        "SELECT * FROM users WHERE email = %s AND company_id = %s",
        (email, company_id)
    )
    user = cur.fetchone()
    cur.close(); conn.close()

    if not user:
        return err("No account found with that email in your company.", 401)
    if not bcrypt.checkpw(password.encode(), user["password"].encode()):
        return err("Incorrect password.", 401)

    token = create_access_token(identity=str(user["id"]))
    return ok({
        "token": token,
        "user": {
            "name":       user["name"],
            "email":      user["email"],
            "role":       user.get("role", "user"),
            "company_id": user["company_id"],
        }
    })


# ══════════════════════════════════════════════
#  EMPLOYEES
# ══════════════════════════════════════════════

@app.route("/api/employees", methods=["POST"])
@jwt_required()
def add_employee():
    b    = request.get_json()
    user = get_current_user()
    cid  = user["company_id"]

    required = ["emp_no","birth_date","first_name","last_name","gender","hire_date"]
    if not all(b.get(f) for f in required):
        return err("All employee fields are required.")

    conn = get_connection(); cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO employees_table
              (company_id, emp_no, birth_date, first_name, last_name, gender, hire_date)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
        """, (cid, b["emp_no"], b["birth_date"], b["first_name"],
              b["last_name"], b["gender"], b["hire_date"]))
        conn.commit()
    except Exception as e:
        conn.rollback(); return err(f"Could not save employee: {str(e)}")
    finally:
        cur.close(); conn.close()
    return ok(msg="Employee saved successfully.", code=201)


@app.route("/api/employees", methods=["GET"])
@jwt_required()
def get_employees():
    user = get_current_user()
    conn = get_connection()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM employees_table WHERE company_id=%s ORDER BY emp_no", (user["company_id"],))
    rows = cur.fetchall()
    cur.close(); conn.close()
    return ok([dict(r) for r in rows])


@app.route("/api/employees/<int:emp_no>", methods=["DELETE"])
@jwt_required()
def delete_employee(emp_no):
    user = get_current_user()
    conn = get_connection(); cur = conn.cursor()
    try:
        cur.execute("DELETE FROM employees_table WHERE company_id=%s AND emp_no=%s", (user["company_id"], emp_no))
        conn.commit()
    except Exception as e:
        conn.rollback(); return err(str(e))
    finally:
        cur.close(); conn.close()
    return ok(msg="Employee deleted.")


@app.route("/api/employees/<int:emp_no>", methods=["PUT"])
@jwt_required()
def update_employee(emp_no):
    b    = request.get_json()
    user = get_current_user()
    conn = get_connection(); cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE employees_table
            SET birth_date=%s, first_name=%s, last_name=%s, gender=%s, hire_date=%s
            WHERE company_id=%s AND emp_no=%s
        """, (b["birth_date"],b["first_name"],b["last_name"],b["gender"],b["hire_date"],
              user["company_id"], emp_no))
        conn.commit()
    except Exception as e:
        conn.rollback(); return err(str(e))
    finally:
        cur.close(); conn.close()
    return ok(msg="Employee updated.")


# ══════════════════════════════════════════════
#  DEPARTMENTS
# ══════════════════════════════════════════════

@app.route("/api/departments", methods=["POST"])
@jwt_required()
def add_department():
    b    = request.get_json()
    user = get_current_user()
    if not b.get("dept_no") or not b.get("dept_name"):
        return err("dept_no and dept_name are required.")

    conn = get_connection(); cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO departments (company_id, dept_no, dept_name) VALUES (%s,%s,%s)",
            (user["company_id"], b["dept_no"], b["dept_name"])
        )
        conn.commit()
    except Exception as e:
        conn.rollback(); return err(f"Could not save department: {str(e)}")
    finally:
        cur.close(); conn.close()
    return ok(msg="Department saved.", code=201)


@app.route("/api/departments", methods=["GET"])
@jwt_required()
def get_departments():
    user = get_current_user()
    conn = get_connection()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM departments WHERE company_id=%s ORDER BY dept_no", (user["company_id"],))
    rows = cur.fetchall()
    cur.close(); conn.close()
    return ok([dict(r) for r in rows])


@app.route("/api/departments/<dept_no>", methods=["DELETE"])
@jwt_required()
def delete_department(dept_no):
    user = get_current_user()
    conn = get_connection(); cur = conn.cursor()
    try:
        cur.execute("DELETE FROM departments WHERE company_id=%s AND dept_no=%s", (user["company_id"], dept_no))
        conn.commit()
    except Exception as e:
        conn.rollback(); return err(str(e))
    finally:
        cur.close(); conn.close()
    return ok(msg="Department deleted.")


@app.route("/api/departments/<dept_no>", methods=["PUT"])
@jwt_required()
def update_department(dept_no):
    b    = request.get_json()
    user = get_current_user()
    conn = get_connection(); cur = conn.cursor()
    try:
        cur.execute(
            "UPDATE departments SET dept_name=%s WHERE company_id=%s AND dept_no=%s",
            (b["dept_name"], user["company_id"], dept_no)
        )
        conn.commit()
    except Exception as e:
        conn.rollback(); return err(str(e))
    finally:
        cur.close(); conn.close()
    return ok(msg="Department updated.")


# ══════════════════════════════════════════════
#  DEPT MANAGER
# ══════════════════════════════════════════════

@app.route("/api/dept_manager", methods=["POST"])
@jwt_required()
def add_dept_manager():
    b    = request.get_json()
    user = get_current_user()
    if not all(b.get(f) for f in ["emp_no","dept_no","from_date","to_date"]):
        return err("All fields are required.")

    conn = get_connection(); cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO dept_manager (company_id, emp_no, dept_no, from_date, to_date)
            VALUES (%s,%s,%s,%s,%s)
        """, (user["company_id"], b["emp_no"], b["dept_no"], b["from_date"], b["to_date"]))
        conn.commit()
    except Exception as e:
        conn.rollback(); return err(f"Could not save: {str(e)}")
    finally:
        cur.close(); conn.close()
    return ok(msg="Dept Manager record saved.", code=201)


@app.route("/api/dept_manager", methods=["GET"])
@jwt_required()
def get_dept_manager():
    user = get_current_user()
    conn = get_connection()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM dept_manager WHERE company_id=%s ORDER BY emp_no", (user["company_id"],))
    rows = cur.fetchall()
    cur.close(); conn.close()
    return ok([dict(r) for r in rows])


@app.route("/api/dept_manager/<int:emp_no>/<dept_no>", methods=["DELETE"])
@jwt_required()
def delete_dept_manager(emp_no, dept_no):
    user = get_current_user()
    conn = get_connection(); cur = conn.cursor()
    try:
        cur.execute(
            "DELETE FROM dept_manager WHERE company_id=%s AND emp_no=%s AND dept_no=%s",
            (user["company_id"], emp_no, dept_no)
        )
        conn.commit()
    except Exception as e:
        conn.rollback(); return err(str(e))
    finally:
        cur.close(); conn.close()
    return ok(msg="Dept manager deleted.")


# ══════════════════════════════════════════════
#  DEPT EMPLOYEES
# ══════════════════════════════════════════════

@app.route("/api/dept_employees", methods=["POST"])
@jwt_required()
def add_dept_employee():
    b    = request.get_json()
    user = get_current_user()
    if not all(b.get(f) for f in ["emp_no","dept_no","from_date","to_date"]):
        return err("All fields are required.")

    conn = get_connection(); cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO dept_employees (company_id, emp_no, dept_no, from_date, to_date)
            VALUES (%s,%s,%s,%s,%s)
        """, (user["company_id"], b["emp_no"], b["dept_no"], b["from_date"], b["to_date"]))
        conn.commit()
    except Exception as e:
        conn.rollback(); return err(f"Could not save: {str(e)}")
    finally:
        cur.close(); conn.close()
    return ok(msg="Dept Employee record saved.", code=201)


@app.route("/api/dept_employees", methods=["GET"])
@jwt_required()
def get_dept_employees():
    user = get_current_user()
    conn = get_connection()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM dept_employees WHERE company_id=%s ORDER BY emp_no", (user["company_id"],))
    rows = cur.fetchall()
    cur.close(); conn.close()
    return ok([dict(r) for r in rows])


@app.route("/api/dept_employees/<int:emp_no>/<dept_no>", methods=["DELETE"])
@jwt_required()
def delete_dept_employee(emp_no, dept_no):
    user = get_current_user()
    conn = get_connection(); cur = conn.cursor()
    try:
        cur.execute(
            "DELETE FROM dept_employees WHERE company_id=%s AND emp_no=%s AND dept_no=%s",
            (user["company_id"], emp_no, dept_no)
        )
        conn.commit()
    except Exception as e:
        conn.rollback(); return err(str(e))
    finally:
        cur.close(); conn.close()
    return ok(msg="Dept employee deleted.")


# ══════════════════════════════════════════════
#  SALARIES
# ══════════════════════════════════════════════

@app.route("/api/salaries", methods=["POST"])
@jwt_required()
def add_salary():
    b    = request.get_json()
    user = get_current_user()
    if not all(b.get(f) for f in ["emp_no","salary","from_date","to_date"]):
        return err("All fields are required.")

    conn = get_connection(); cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO salaries (company_id, emp_no, salary, from_date, to_date)
            VALUES (%s,%s,%s,%s,%s)
        """, (user["company_id"], b["emp_no"], b["salary"], b["from_date"], b["to_date"]))
        conn.commit()
    except Exception as e:
        conn.rollback(); return err(f"Could not save: {str(e)}")
    finally:
        cur.close(); conn.close()
    return ok(msg="Salary record saved.", code=201)


@app.route("/api/salaries", methods=["GET"])
@jwt_required()
def get_salaries():
    user = get_current_user()
    conn = get_connection()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM salaries WHERE company_id=%s ORDER BY emp_no", (user["company_id"],))
    rows = cur.fetchall()
    cur.close(); conn.close()
    return ok([dict(r) for r in rows])


@app.route("/api/salaries/<int:emp_no>/<from_date>", methods=["DELETE"])
@jwt_required()
def delete_salary(emp_no, from_date):
    user = get_current_user()
    conn = get_connection(); cur = conn.cursor()
    try:
        cur.execute(
            "DELETE FROM salaries WHERE company_id=%s AND emp_no=%s AND from_date=%s",
            (user["company_id"], emp_no, from_date)
        )
        conn.commit()
    except Exception as e:
        conn.rollback(); return err(str(e))
    finally:
        cur.close(); conn.close()
    return ok(msg="Salary deleted.")


@app.route("/api/salaries/<int:emp_no>/<from_date>", methods=["PUT"])
@jwt_required()
def update_salary(emp_no, from_date):
    b    = request.get_json()
    user = get_current_user()
    conn = get_connection(); cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE salaries SET salary=%s, to_date=%s
            WHERE company_id=%s AND emp_no=%s AND from_date=%s
        """, (b["salary"], b["to_date"], user["company_id"], emp_no, from_date))
        conn.commit()
    except Exception as e:
        conn.rollback(); return err(str(e))
    finally:
        cur.close(); conn.close()
    return ok(msg="Salary updated.")


# ══════════════════════════════════════════════
#  REPORTS
# ══════════════════════════════════════════════

@app.route("/api/reports/summary", methods=["GET"])
@jwt_required()
def report_summary():
    user = get_current_user()
    cid  = user["company_id"]
    conn = get_connection()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute("SELECT COUNT(*) AS total FROM employees_table WHERE company_id=%s", (cid,))
    total_employees = cur.fetchone()["total"]

    cur.execute("SELECT COUNT(*) AS total FROM departments WHERE company_id=%s", (cid,))
    total_departments = cur.fetchone()["total"]

    cur.execute("SELECT ROUND(AVG(salary)::numeric,2) AS avg FROM salaries WHERE company_id=%s", (cid,))
    avg_salary = cur.fetchone()["avg"] or 0

    cur.execute("""
        SELECT gender, COUNT(*) AS count
        FROM employees_table WHERE company_id=%s GROUP BY gender
    """, (cid,))
    gender = [dict(r) for r in cur.fetchall()]

    cur.execute("""
        SELECT d.dept_name, COUNT(de.emp_no) AS count
        FROM departments d
        LEFT JOIN dept_employees de ON d.dept_no=de.dept_no AND d.company_id=de.company_id
        WHERE d.company_id=%s
        GROUP BY d.dept_name ORDER BY count DESC
    """, (cid,))
    per_dept = [dict(r) for r in cur.fetchall()]

    cur.execute("""
        SELECT d.dept_name, ROUND(AVG(s.salary)::numeric,0) AS avg_salary
        FROM salaries s
        JOIN dept_employees de ON s.emp_no=de.emp_no AND s.company_id=de.company_id
        JOIN departments d ON de.dept_no=d.dept_no AND de.company_id=d.company_id
        WHERE s.company_id=%s
        GROUP BY d.dept_name ORDER BY avg_salary DESC
    """, (cid,))
    salary_by_dept = [dict(r) for r in cur.fetchall()]

    cur.execute("""
        SELECT EXTRACT(YEAR FROM hire_date)::int AS year, COUNT(*) AS count
        FROM employees_table WHERE company_id=%s
        GROUP BY year ORDER BY year
    """, (cid,))
    hires_by_year = [dict(r) for r in cur.fetchall()]

    cur.close(); conn.close()

    return ok({
        "total_employees":    total_employees,
        "total_departments":  total_departments,
        "avg_salary":         float(avg_salary),
        "gender_split":       gender,
        "employees_per_dept": per_dept,
        "salary_by_dept":     salary_by_dept,
        "hires_by_year":      hires_by_year,
    })


# ══════════════════════════════════════════════
#  CHAT
# ══════════════════════════════════════════════

@app.route("/api/messages", methods=["GET"])
@jwt_required()
def get_messages():
    user = get_current_user()
    conn = get_connection()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT id, user_name, user_email, content, created_at
        FROM messages WHERE company_id=%s
        ORDER BY created_at ASC LIMIT 100
    """, (user["company_id"],))
    rows = cur.fetchall()
    cur.close(); conn.close()
    return ok([dict(r) for r in rows])


@app.route("/api/messages", methods=["POST"])
@jwt_required()
def send_message():
    body    = request.get_json()
    content = (body.get("content") or "").strip()
    if not content:
        return err("Message cannot be empty.")
    if len(content) > 1000:
        return err("Message too long. Max 1000 characters.")

    user = get_current_user()
    conn = get_connection()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute("""
            INSERT INTO messages (company_id, user_name, user_email, content, created_at)
            VALUES (%s,%s,%s,%s,NOW())
            RETURNING id, user_name, user_email, content, created_at
        """, (user["company_id"], user["name"], user["email"], content))
        msg = dict(cur.fetchone())
        conn.commit()
    except Exception as e:
        conn.rollback(); return err(f"Could not send message: {str(e)}")
    finally:
        cur.close(); conn.close()
    return ok(format_dates(msg), msg="Message sent.", code=201)


# ── Init DB ──────────────────────────────────
init_db()

# ── Run (local dev only) ─────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)