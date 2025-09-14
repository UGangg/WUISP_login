from flask import Flask, request, make_response, redirect, render_template
import sqlite3, os

app = Flask(__name__)
DB_PATH = "app.db"

def get_conn():
    return sqlite3.connect(DB_PATH)

def init_db():
    if not os.path.exists(DB_PATH):
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            is_admin INTEGER DEFAULT 0
        );
        """)
        # 데모 계정
        cur.execute("INSERT INTO users (username, password, is_admin) VALUES ('admin','admin123',1)")
        cur.execute("INSERT INTO users (username, password, is_admin) VALUES ('alice','alice123',0)")
        conn.commit()
        conn.close()

@app.route("/")
def index():
    # 의도적 취약: URL ?uid= 값을 신뢰하여 계정 전환 허용
    uid_param = request.args.get("uid")
    uid_cookie = request.cookies.get("uid")

    # 우선순위: URL 파라미터가 있으면 그 값을 신뢰하고 쿠키도 그 값으로 갱신
    active_uid = uid_param if uid_param is not None else uid_cookie

    username = None
    if active_uid:
        conn = get_conn()
        cur = conn.cursor()
        # 조회 자체는 안전 바인딩(취약점은 "URL 값을 신뢰"하는 로직에 있음)
        cur.execute("SELECT username FROM users WHERE id = ?", (active_uid,))
        row = cur.fetchone()
        conn.close()
        if row:
            username = row[0]

    # 응답 생성
    resp = make_response(render_template("index.html", username=username))
    if uid_param is not None:
        # URL이 있으면 쿠키를 그 값으로 덮어써 계정 전환 상태를 유지
        resp.set_cookie("uid", uid_param)
    return resp

# -------------------- 회원가입 (의도적 SQLi / 화면 노출 최소화) --------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # ⚠️ 고의적 취약: 파라미터 바인딩 미사용 (SQLi 가능)
    sql = f"INSERT INTO users (username, password) VALUES ('{username}','{password}')"
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(sql)  # 취약 지점
        conn.commit()
        conn.close()
        return redirect("/login")
    except Exception:
        # 구체 에러/SQL 노출 없이 일반 오류 메시지
        return render_template("signup.html", err="가입에 실패했습니다. 다시 시도해 주세요."), 400

# -------------------- 로그인 (의도적 SQLi + 취약 쿠키 / 화면 노출 최소화) --------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # ⚠️ 고의적 취약: 바인딩 없음 (SQLi 가능)
    sql = f"SELECT id FROM users WHERE username='{username}' AND password='{password}'"

    conn = get_conn()
    cur = conn.cursor()
    try:
        cur.execute(sql)  # 취약 지점
        row = cur.fetchone()
    except Exception:
        conn.close()
        return render_template("login.html", err="오류가 발생했습니다. 잠시 후 다시 시도해 주세요."), 400
    conn.close()

    if row:
        user_id = row[0]
        resp = make_response(redirect("/"))
        # ⚠️ 취약 쿠키: HttpOnly/Secure/SameSite 미설정
        resp.set_cookie("uid", str(user_id))
        return resp

    return render_template("login.html", err="아이디 또는 비밀번호가 올바르지 않습니다."), 401

@app.route("/logout")
def logout():
    resp = make_response(redirect("/"))
    resp.delete_cookie("uid")
    return resp

if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
