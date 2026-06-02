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
    """Recursively convert date/datetime objects to YYYY-MM-DD strings."""
    if isinstance(obj, list):
        return [format_dates(i) for i in obj]
    if isinstance(obj, dict):
        return {k: format_dates(v) for k, v in obj.items()}
    if isinstance(obj, (datetime.date, datetime.datetime)):
        return obj.strftime("%Y-%m-%d")
    return obj

def ok(data=None, msg="success", code=200):
    return jsonify({"status": "ok", "message": msg, "data": format_dates(data)}), code

def err(msg, code=400):
    return jsonify({"status": "error", "message": msg}), code


# ══════════════════════════════════════════════
#  AUTH ROUTES
# ══════════════════════════════════════════════

@app.route("/api/signup", methods=["POST"])
def signup():
    body = request.get_json()
    name     = (body.get("name") or "").strip()
    email    = (body.get("email") or "").strip().lower()
    password = (body.get("password") or "")

    if not name or not email or not password:
        return err("All fields are required.")
    if len(password) < 6:
        return err("Password must be at least 6 characters.")

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    role = body.get("role", "user")
    if role not in ["admin", "user"]:
        role = "user"

    conn = get_connection()
    cur  = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (name, email, password, role) VALUES (%s, %s, %s, %s)",
            (name, email, hashed, role)
        )
        conn.commit()
    except Exception:
        conn.rollback()
        return err("An account with this email already exists.")
    finally:
        cur.close(); conn.close()

    return ok(msg="Account created successfully.", code=201)


@app.route("/api/signin", methods=["POST"])
def signin():
    body = request.get_json()
    email    = (body.get("email") or "").strip().lower()
    password = (body.get("password") or "")

    conn = get_connection()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cur.fetchone()
    cur.close(); conn.close()

    if not user:
        return err("No account found with that email.", 401)
    if not bcrypt.checkpw(password.encode(), user["password"].encode()):
        return err("Incorrect password.", 401)

    token = create_access_token(identity=str(user["id"]))
    return ok({
        "token": token,
        "user": {"name": user["name"], "email": user["email"], "role": user.get("role", "user")}
    })


# ══════════════════════════════════════════════
#  EMPLOYEES
# ══════════════════════════════════════════════

@app.route("/api/employees", methods=["POST"])
@jwt_required()
def add_employee():
    b = request.get_json()
    required = ["emp_no","birth_date","first_name","last_name","gender","hire_date"]
    if not all(b.get(f) for f in required):
        return err("All employee fields are required.")

    conn = get_connection()
    cur  = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO employees_table
              (emp_no, birth_date, first_name, last_name, gender, hire_date)
            VALUES (%s,%s,%s,%s,%s,%s)
        """, (b["emp_no"], b["birth_date"], b["first_name"],
              b["last_name"], b["gender"], b["hire_date"]))
        conn.commit()
    except Exception as e:
        conn.rollback()
        return err(f"Could not save employee: {str(e)}")
    finally:
        cur.close(); conn.close()

    return ok(msg="Employee saved successfully.", code=201)


@app.route("/api/employees", methods=["GET"])
@jwt_required()
def get_employees():
    conn = get_connection()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM employees_table ORDER BY emp_no")
    rows = cur.fetchall()
    cur.close(); conn.close()
    return ok([dict(r) for r in rows])


# ══════════════════════════════════════════════
#  DEPARTMENTS
# ══════════════════════════════════════════════

@app.route("/api/departments", methods=["POST"])
@jwt_required()
def add_department():
    b = request.get_json()
    if not b.get("dept_no") or not b.get("dept_name"):
        return err("dept_no and dept_name are required.")

    conn = get_connection()
    cur  = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO departments (dept_no, dept_name) VALUES (%s, %s)",
            (b["dept_no"], b["dept_name"])
        )
        conn.commit()
    except Exception as e:
        conn.rollback()
        return err(f"Could not save department: {str(e)}")
    finally:
        cur.close(); conn.close()

    return ok(msg="Department saved.", code=201)


@app.route("/api/departments", methods=["GET"])
@jwt_required()
def get_departments():
    conn = get_connection()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM departments ORDER BY dept_no")
    rows = cur.fetchall()
    cur.close(); conn.close()
    return ok([dict(r) for r in rows])


# ══════════════════════════════════════════════
#  DEPT MANAGER
# ══════════════════════════════════════════════

@app.route("/api/dept_manager", methods=["POST"])
@jwt_required()
def add_dept_manager():
    b = request.get_json()
    required = ["emp_no","dept_no","from_date","to_date"]
    if not all(b.get(f) for f in required):
        return err("All fields are required.")

    conn = get_connection()
    cur  = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO dept_manager (emp_no, dept_no, from_date, to_date)
            VALUES (%s,%s,%s,%s)
        """, (b["emp_no"], b["dept_no"], b["from_date"], b["to_date"]))
        conn.commit()
    except Exception as e:
        conn.rollback()
        return err(f"Could not save: {str(e)}")
    finally:
        cur.close(); conn.close()

    return ok(msg="Dept Manager record saved.", code=201)


@app.route("/api/dept_manager", methods=["GET"])
@jwt_required()
def get_dept_manager():
    conn = get_connection()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM dept_manager ORDER BY emp_no")
    rows = cur.fetchall()
    cur.close(); conn.close()
    return ok([dict(r) for r in rows])


# ══════════════════════════════════════════════
#  DEPT EMPLOYEES
# ══════════════════════════════════════════════

@app.route("/api/dept_employees", methods=["POST"])
@jwt_required()
def add_dept_employee():
    b = request.get_json()
    required = ["emp_no","dept_no","from_date","to_date"]
    if not all(b.get(f) for f in required):
        return err("All fields are required.")

    conn = get_connection()
    cur  = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO dept_employees (emp_no, dept_no, from_date, to_date)
            VALUES (%s,%s,%s,%s)
        """, (b["emp_no"], b["dept_no"], b["from_date"], b["to_date"]))
        conn.commit()
    except Exception as e:
        conn.rollback()
        return err(f"Could not save: {str(e)}")
    finally:
        cur.close(); conn.close()

    return ok(msg="Dept Employee record saved.", code=201)


@app.route("/api/dept_employees", methods=["GET"])
@jwt_required()
def get_dept_employees():
    conn = get_connection()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM dept_employees ORDER BY emp_no")
    rows = cur.fetchall()
    cur.close(); conn.close()
    return ok([dict(r) for r in rows])


# ══════════════════════════════════════════════
#  SALARIES
# ══════════════════════════════════════════════

@app.route("/api/salaries", methods=["POST"])
@jwt_required()
def add_salary():
    b = request.get_json()
    required = ["emp_no","salary","from_date","to_date"]
    if not all(b.get(f) for f in required):
        return err("All fields are required.")

    conn = get_connection()
    cur  = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO salaries (emp_no, salary, from_date, to_date)
            VALUES (%s,%s,%s,%s)
        """, (b["emp_no"], b["salary"], b["from_date"], b["to_date"]))
        conn.commit()
    except Exception as e:
        conn.rollback()
        return err(f"Could not save: {str(e)}")
    finally:
        cur.close(); conn.close()

    return ok(msg="Salary record saved.", code=201)


@app.route("/api/salaries", methods=["GET"])
@jwt_required()
def get_salaries():
    conn = get_connection()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM salaries ORDER BY emp_no")
    rows = cur.fetchall()
    cur.close(); conn.close()
    return ok([dict(r) for r in rows])


# ══════════════════════════════════════════════
#  REPORTS / DASHBOARD DATA
# ══════════════════════════════════════════════

@app.route("/api/reports/summary", methods=["GET"])
@jwt_required()
def report_summary():
    conn = get_connection()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cur.execute("SELECT COUNT(*) AS total FROM employees_table")
    total_employees = cur.fetchone()["total"]

    cur.execute("SELECT COUNT(*) AS total FROM departments")
    total_departments = cur.fetchone()["total"]

    cur.execute("SELECT ROUND(AVG(salary)::numeric, 2) AS avg FROM salaries")
    avg_salary = cur.fetchone()["avg"] or 0

    cur.execute("""
        SELECT gender, COUNT(*) AS count
        FROM employees_table GROUP BY gender
    """)
    gender = [dict(r) for r in cur.fetchall()]

    cur.execute("""
        SELECT d.dept_name, COUNT(de.emp_no) AS count
        FROM departments d
        LEFT JOIN dept_employees de ON d.dept_no = de.dept_no
        GROUP BY d.dept_name
        ORDER BY count DESC
    """)
    per_dept = [dict(r) for r in cur.fetchall()]

    cur.execute("""
        SELECT d.dept_name, ROUND(AVG(s.salary)::numeric, 0) AS avg_salary
        FROM salaries s
        JOIN dept_employees de ON s.emp_no = de.emp_no
        JOIN departments d ON de.dept_no = d.dept_no
        GROUP BY d.dept_name
        ORDER BY avg_salary DESC
    """)
    salary_by_dept = [dict(r) for r in cur.fetchall()]

    cur.execute("""
        SELECT EXTRACT(YEAR FROM hire_date)::int AS year, COUNT(*) AS count
        FROM employees_table
        GROUP BY year ORDER BY year
    """)
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
#  DELETE & UPDATE ROUTES
# ══════════════════════════════════════════════

@app.route("/api/employees/<int:emp_no>", methods=["DELETE"])
@jwt_required()
def delete_employee(emp_no):
    conn = get_connection(); cur = conn.cursor()
    try:
        cur.execute("DELETE FROM employees_table WHERE emp_no = %s", (emp_no,))
        conn.commit()
    except Exception as e:
        conn.rollback(); return err(str(e))
    finally:
        cur.close(); conn.close()
    return ok(msg="Employee deleted.")

@app.route("/api/employees/<int:emp_no>", methods=["PUT"])
@jwt_required()
def update_employee(emp_no):
    b = request.get_json()
    conn = get_connection(); cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE employees_table
            SET birth_date=%s, first_name=%s, last_name=%s, gender=%s, hire_date=%s
            WHERE emp_no=%s
        """, (b["birth_date"],b["first_name"],b["last_name"],b["gender"],b["hire_date"],emp_no))
        conn.commit()
    except Exception as e:
        conn.rollback(); return err(str(e))
    finally:
        cur.close(); conn.close()
    return ok(msg="Employee updated.")

@app.route("/api/departments/<dept_no>", methods=["DELETE"])
@jwt_required()
def delete_department(dept_no):
    conn = get_connection(); cur = conn.cursor()
    try:
        cur.execute("DELETE FROM departments WHERE dept_no = %s", (dept_no,))
        conn.commit()
    except Exception as e:
        conn.rollback(); return err(str(e))
    finally:
        cur.close(); conn.close()
    return ok(msg="Department deleted.")

@app.route("/api/departments/<dept_no>", methods=["PUT"])
@jwt_required()
def update_department(dept_no):
    b = request.get_json()
    conn = get_connection(); cur = conn.cursor()
    try:
        cur.execute("UPDATE departments SET dept_name=%s WHERE dept_no=%s", (b["dept_name"], dept_no))
        conn.commit()
    except Exception as e:
        conn.rollback(); return err(str(e))
    finally:
        cur.close(); conn.close()
    return ok(msg="Department updated.")

@app.route("/api/dept_manager/<int:emp_no>/<dept_no>", methods=["DELETE"])
@jwt_required()
def delete_dept_manager(emp_no, dept_no):
    conn = get_connection(); cur = conn.cursor()
    try:
        cur.execute("DELETE FROM dept_manager WHERE emp_no=%s AND dept_no=%s", (emp_no, dept_no))
        conn.commit()
    except Exception as e:
        conn.rollback(); return err(str(e))
    finally:
        cur.close(); conn.close()
    return ok(msg="Dept manager deleted.")

@app.route("/api/dept_employees/<int:emp_no>/<dept_no>", methods=["DELETE"])
@jwt_required()
def delete_dept_employee(emp_no, dept_no):
    conn = get_connection(); cur = conn.cursor()
    try:
        cur.execute("DELETE FROM dept_employees WHERE emp_no=%s AND dept_no=%s", (emp_no, dept_no))
        conn.commit()
    except Exception as e:
        conn.rollback(); return err(str(e))
    finally:
        cur.close(); conn.close()
    return ok(msg="Dept employee deleted.")

@app.route("/api/salaries/<int:emp_no>/<from_date>", methods=["DELETE"])
@jwt_required()
def delete_salary(emp_no, from_date):
    conn = get_connection(); cur = conn.cursor()
    try:
        cur.execute("DELETE FROM salaries WHERE emp_no=%s AND from_date=%s", (emp_no, from_date))
        conn.commit()
    except Exception as e:
        conn.rollback(); return err(str(e))
    finally:
        cur.close(); conn.close()
    return ok(msg="Salary deleted.")

@app.route("/api/salaries/<int:emp_no>/<from_date>", methods=["PUT"])
@jwt_required()
def update_salary(emp_no, from_date):
    b = request.get_json()
    conn = get_connection(); cur = conn.cursor()
    try:
        cur.execute("""
            UPDATE salaries SET salary=%s, to_date=%s
            WHERE emp_no=%s AND from_date=%s
        """, (b["salary"], b["to_date"], emp_no, from_date))
        conn.commit()
    except Exception as e:
        conn.rollback(); return err(str(e))
    finally:
        cur.close(); conn.close()
    return ok(msg="Salary updated.")
    
    # ══════════════════════════════════════════════
#  CHAT ROUTES
# ══════════════════════════════════════════════

@app.route("/api/messages", methods=["GET"])
@jwt_required()
def get_messages():
    conn = get_connection()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("""
        SELECT id, user_name, user_email, content, created_at
        FROM messages
        ORDER BY created_at ASC
        LIMIT 100
    """)
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

    identity = get_jwt_identity()

    conn = get_connection()
    cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # Get user info from token
    cur.execute("SELECT name, email FROM users WHERE id = %s", (identity,))
    user = cur.fetchone()
    if not user:
        cur.close(); conn.close()
        return err("User not found.", 401)

    cur2 = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur2.execute("""
    INSERT INTO messages (user_name, user_email, content, created_at)
    VALUES (%s, %s, %s, NOW())
    RETURNING id, user_name, user_email, content, created_at
""", (user["name"], user["email"], content))


        msg = dict(cur2.fetchone())
        conn.commit()
    except Exception as e:
        conn.rollback()
        return err(f"Could not send message: {str(e)}")
    finally:
        cur.close(); cur2.close(); conn.close()

    return ok(format_dates(msg), msg="Message sent.", code=201)


# ── Init DB on startup ───────────────────────
init_db()

# ── Run (local dev only) ─────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
