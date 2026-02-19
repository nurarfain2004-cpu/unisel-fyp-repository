import os
import re
import time
import hashlib
import smtplib
from dotenv import load_dotenv

load_dotenv()

from email.message import EmailMessage
from pathlib import Path
from typing import List
from datetime import datetime

from fastapi import FastAPI, Request, Form, Depends, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.status import HTTP_302_FOUND
from fastapi.templating import Jinja2Templates

from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, text
from sqlalchemy.orm import declarative_base, sessionmaker, Session

# --- Optional PDF extraction dependency ---
try:
    import pdfplumber
except Exception:
    pdfplumber = None


# =========================
# CONFIG
# =========================
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "fyp_repository.db"
UPLOADS_DIR = BASE_DIR / "uploads"
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
PROFILE_DIR = STATIC_DIR / "profiles"

UPLOADS_DIR.mkdir(exist_ok=True)
TEMPLATES_DIR.mkdir(exist_ok=True)
STATIC_DIR.mkdir(exist_ok=True)
PROFILE_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = f"sqlite:///{DB_PATH}"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)
Base = declarative_base()

app = FastAPI(title="Unisel FYP Repository")

# Session
SESSION_SECRET = os.getenv("SESSION_SECRET", "CHANGE_THIS_SECRET_KEY_NOW")
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)

# Static
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


# =========================
# DATABASE MODELS
# =========================
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    name = Column(String(200), default="")
    email = Column(String(200), unique=True, nullable=False)
    password_hash = Column(String(300), nullable=False)
    role = Column(String(50), nullable=False)  # student | supervisor | admin
    profile_pic = Column(String(500), default="")  # /static/profiles/xxx.png
    created_at = Column(DateTime, default=datetime.utcnow)


class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True)
    doc_no = Column(String(50), default="")
    title = Column(String(300), nullable=False)
    abstract = Column(Text, nullable=False)
    filename = Column(String(300), nullable=False)
    file_path = Column(String(500), nullable=False)
    uploaded_by = Column(String(200), default="")
    status = Column(String(50), default="approved")
    created_at = Column(DateTime, default=datetime.utcnow)


class AccessRequest(Base):
    __tablename__ = "access_requests"
    id = Column(Integer, primary_key=True)
    report_id = Column(Integer, nullable=False)
    student_name = Column(String(200), nullable=False)
    matric_no = Column(String(100), nullable=False)
    student_email = Column(String(200), nullable=False)
    reason = Column(Text, nullable=False)
    status = Column(String(50), default="pending")  # pending/approved/rejected
    reviewed_by = Column(String(200), default="")
    reviewed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)


# =========================
# MIGRATION (safe add missing columns)
# =========================
def _col_exists(db: Session, table: str, col: str) -> bool:
    rows = db.execute(text(f"PRAGMA table_info({table})")).fetchall()
    return any(r[1] == col for r in rows)


def migrate_sqlite_schema():
    db = SessionLocal()
    try:
        # users
        if not _col_exists(db, "users", "name"):
            db.execute(text("ALTER TABLE users ADD COLUMN name VARCHAR(200) DEFAULT ''"))
        if not _col_exists(db, "users", "created_at"):
            db.execute(text("ALTER TABLE users ADD COLUMN created_at DATETIME"))
        if not _col_exists(db, "users", "profile_pic"):
            db.execute(text("ALTER TABLE users ADD COLUMN profile_pic VARCHAR(500) DEFAULT ''"))

        # reports
        if not _col_exists(db, "reports", "doc_no"):
            db.execute(text("ALTER TABLE reports ADD COLUMN doc_no VARCHAR(50) DEFAULT ''"))
        if not _col_exists(db, "reports", "created_at"):
            db.execute(text("ALTER TABLE reports ADD COLUMN created_at DATETIME"))
        if not _col_exists(db, "reports", "status"):
            db.execute(text("ALTER TABLE reports ADD COLUMN status VARCHAR(50) DEFAULT 'approved'"))
        if not _col_exists(db, "reports", "uploaded_by"):
            db.execute(text("ALTER TABLE reports ADD COLUMN uploaded_by VARCHAR(200) DEFAULT ''"))

        # access_requests
        if not _col_exists(db, "access_requests", "reviewed_by"):
            db.execute(text("ALTER TABLE access_requests ADD COLUMN reviewed_by VARCHAR(200) DEFAULT ''"))
        if not _col_exists(db, "access_requests", "reviewed_at"):
            db.execute(text("ALTER TABLE access_requests ADD COLUMN reviewed_at DATETIME"))
        if not _col_exists(db, "access_requests", "created_at"):
            db.execute(text("ALTER TABLE access_requests ADD COLUMN created_at DATETIME"))

        db.commit()
    finally:
        db.close()


migrate_sqlite_schema()


# =========================
# DB DEP
# =========================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# =========================
# HELPERS (AUTH)
# =========================
def hash_password(pw: str) -> str:
    salt = os.getenv("PW_SALT", "uniselfyp_salt")
    return hashlib.sha256((salt + pw).encode("utf-8")).hexdigest()


def require_login(request: Request):
    if not request.session.get("email"):
        raise HTTPException(status_code=401, detail="Not logged in")


def require_role(request: Request, roles: List[str]):
    require_login(request)
    role = (request.session.get("role") or "").lower()
    if role not in roles:
        raise HTTPException(status_code=403, detail="Forbidden")


def current_user_email(request: Request) -> str:
    return request.session.get("email") or ""


def current_role(request: Request) -> str:
    return (request.session.get("role") or "").lower()


def dashboard_url_for(role: str) -> str:
    role = (role or "").lower()
    if role == "student":
        return "/student-dashboard"
    if role == "supervisor":
        return "/supervisor-dashboard"
    if role == "admin":
        return "/admin-dashboard"
    return "/login-page"


def common_ctx(request: Request) -> dict:
    role = current_role(request)
    profile = request.session.get("profile_pic", "") or "/static/default_avatar.png"
    return {
        "request": request,
        "name": request.session.get("name", ""),
        "role": role,
        "profile_pic": profile,
        "dashboard_url": dashboard_url_for(role),
    }


def render(request: Request, template_name: str, extra: dict = None):
    ctx = common_ctx(request)
    if extra:
        ctx.update(extra)
    return templates.TemplateResponse(template_name, ctx)


# =========================
# HELPERS (EMAIL)  ✅ IMPROVED (LESS SPAM)
# =========================
def send_status_email(to_email: str, subject: str, body: str):
    sender = os.getenv("GMAIL_SENDER", "")
    app_pw = os.getenv("GMAIL_APP_PASSWORD", "")

    # Debug prints help you verify where it was sent
    print("---- EMAIL DEBUG ----")
    print("FROM:", sender)
    print("TO:", to_email)
    print("SUBJECT:", subject)

    if not sender or not app_pw:
        print("EMAIL NOT SENT: Missing GMAIL_SENDER or GMAIL_APP_PASSWORD env vars.")
        print("----------------------")
        return

    msg = EmailMessage()
    # Friendlier From-name (less spammy)
    msg["From"] = f"UNISEL FYP Repository <{sender}>"
    msg["To"] = to_email
    msg["Reply-To"] = sender
    msg["Subject"] = subject

    # Add a small footer (also reduces spam filtering)
    msg.set_content(
        body
        + "\n\n---\nUNISEL FYP Repository System\nThis is an automated message. Please do not reply."
    )

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(sender, app_pw)
            smtp.send_message(msg)
        print(f"EMAIL SENT to {to_email} ✅")
    except smtplib.SMTPAuthenticationError as e:
        print("EMAIL FAILED ❌ AUTH ERROR:", str(e))
    except smtplib.SMTPRecipientsRefused as e:
        print("EMAIL FAILED ❌ RECIPIENT REFUSED:", str(e))
    except Exception as e:
        print("EMAIL FAILED ❌:", str(e))

    print("----------------------")


# =========================
# HELPERS (FILES)
# =========================
def _safe_filename(original: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", original)


def _save_profile_pic(file: UploadFile) -> str:
    if not file or not file.filename:
        return ""
    fn = file.filename.lower()
    if not (fn.endswith(".png") or fn.endswith(".jpg") or fn.endswith(".jpeg")):
        raise HTTPException(status_code=400, detail="Profile picture must be PNG/JPG/JPEG")

    safe = _safe_filename(file.filename)
    name = f"{int(time.time())}_{safe}"
    path = PROFILE_DIR / name
    with open(path, "wb") as f:
        f.write(file.file.read())
    return f"/static/profiles/{name}"


def _delete_profile_pic_if_local(url_path: str):
    if not url_path:
        return
    if not url_path.startswith("/static/profiles/"):
        return
    fn = url_path.replace("/static/profiles/", "")
    p = PROFILE_DIR / fn
    try:
        if p.exists():
            p.unlink()
    except Exception:
        pass


# =========================
# HELPERS (PDF EXTRACT)
# =========================
def clean_text(text_: str) -> str:
    text_ = text_.replace("\r", "\n")
    text_ = re.sub(r"[ \t]+", " ", text_)
    text_ = re.sub(r"\n{3,}", "\n\n", text_)
    return text_.strip()


def extract_title_and_abstract(pdf_path: Path, fallback_filename: str) -> (str, str):
    if pdfplumber is None:
        raise Exception("pdfplumber not installed. Run: pip install pdfplumber")

    pages_text = []
    with pdfplumber.open(str(pdf_path)) as pdf:
        for i in range(min(3, len(pdf.pages))):
            pages_text.append(pdf.pages[i].extract_text() or "")

    raw = clean_text("\n\n".join(pages_text))
    lines = [l.strip() for l in raw.splitlines() if l.strip()]

    title = Path(fallback_filename).stem
    for l in lines[:20]:
        if len(l) >= 10 and not re.match(r"^\d+$", l):
            if l.lower() in ["abstract", "acknowledgement", "acknowledgment"]:
                continue
            title = l
            break

    abstract = ""
    m = re.search(r"(?is)\babstract\b\s*[:\-]?\s*(.+)", raw)
    if m:
        after = m.group(1)
        stops = [
            r"\backnowledg(e)?ment\b",
            r"\bkeywords\b",
            r"\bchapter\b",
            r"\btable of contents\b",
            r"\bintroduction\b",
        ]
        stop_idx = None
        lower = after.lower()
        for s in stops:
            mm = re.search(s, lower)
            if mm and mm.start() > 50:
                stop_idx = mm.start()
                break
        chunk = after[:stop_idx] if stop_idx else after
        abstract = clean_text(chunk)[:3500]

    if not abstract:
        abstract = clean_text(raw)[:1500]

    return title.strip(), abstract.strip()


# =========================
# HOME
# =========================
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    if request.session.get("email"):
        return RedirectResponse(dashboard_url_for(current_role(request)), status_code=HTTP_302_FOUND)
    return RedirectResponse("/login-page", status_code=HTTP_302_FOUND)


# =========================
# REGISTER / LOGIN (OPTION A)
# =========================
@app.get("/register-page", response_class=HTMLResponse)
def register_page(request: Request):
    return render(request, "register.html")


@app.post("/register")
def register(
    request: Request,
    db: Session = Depends(get_db),
    name: str = Form(""),
    email: str = Form(...),
    password: str = Form(...),
    profile_pic: UploadFile = File(None)
):
    role = "student"

    email_clean = email.strip().lower()
    exists = db.query(User).filter(User.email == email_clean).first()
    if exists:
        return render(request, "register.html", {"error": "Email already registered."})

    pic_url = ""
    try:
        if profile_pic and profile_pic.filename:
            pic_url = _save_profile_pic(profile_pic)
    except HTTPException as e:
        return render(request, "register.html", {"error": e.detail})

    u = User(
        name=name.strip(),
        email=email_clean,
        password_hash=hash_password(password),
        role=role,
        profile_pic=pic_url
    )
    db.add(u)
    db.commit()

    return RedirectResponse("/login-page", status_code=HTTP_302_FOUND)


@app.get("/login-page", response_class=HTMLResponse)
def login_page(request: Request):
    return render(request, "login.html")


@app.post("/login")
def login(
    request: Request,
    db: Session = Depends(get_db),
    email: str = Form(...),
    password: str = Form(...)
):
    email_clean = email.strip().lower()
    u = db.query(User).filter(User.email == email_clean).first()
    if not u or u.password_hash != hash_password(password):
        return render(request, "login.html", {"error": "Invalid email/password."})

    request.session["email"] = u.email
    request.session["role"] = u.role
    request.session["name"] = u.name
    request.session["profile_pic"] = u.profile_pic or ""

    return RedirectResponse(dashboard_url_for(u.role), status_code=HTTP_302_FOUND)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login-page", status_code=HTTP_302_FOUND)


# =========================
# PROFILE
# =========================
@app.get("/profile", response_class=HTMLResponse)
def profile_edit_page(request: Request, db: Session = Depends(get_db)):
    require_login(request)
    email = current_user_email(request)
    u = db.query(User).filter(User.email == email).first()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    return render(request, "profile_edit.html", {"user": u})


@app.post("/profile-update")
def profile_update(
    request: Request,
    db: Session = Depends(get_db),
    name: str = Form(""),
    email: str = Form(""),
    current_password: str = Form(""),
    new_password: str = Form(""),
    profile_pic: UploadFile = File(None)
):
    require_login(request)
    session_email = current_user_email(request)
    u = db.query(User).filter(User.email == session_email).first()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    wants_email_change = email.strip().lower() and email.strip().lower() != u.email
    wants_pw_change = bool(new_password.strip())

    if wants_email_change or wants_pw_change:
        if not current_password or hash_password(current_password) != u.password_hash:
            return render(request, "profile_edit.html", {"user": u, "error": "Current password is incorrect."})

    if name.strip():
        u.name = name.strip()

    if wants_email_change:
        new_email = email.strip().lower()
        exists = db.query(User).filter(User.email == new_email).first()
        if exists:
            return render(request, "profile_edit.html", {"user": u, "error": "Email already in use."})
        u.email = new_email

    if wants_pw_change:
        u.password_hash = hash_password(new_password.strip())

    if profile_pic and profile_pic.filename:
        try:
            new_pic = _save_profile_pic(profile_pic)
            _delete_profile_pic_if_local(u.profile_pic or "")
            u.profile_pic = new_pic
        except HTTPException as e:
            return render(request, "profile_edit.html", {"user": u, "error": str(e.detail)})

    db.commit()

    request.session["name"] = u.name
    request.session["email"] = u.email
    request.session["profile_pic"] = u.profile_pic or ""

    return RedirectResponse("/profile", status_code=HTTP_302_FOUND)


# =========================
# DASHBOARDS
# =========================
@app.get("/student-dashboard", response_class=HTMLResponse)
def student_dashboard(request: Request):
    require_role(request, ["student"])
    return render(request, "student_dashboard.html")


@app.get("/supervisor-dashboard", response_class=HTMLResponse)
def supervisor_dashboard(request: Request):
    require_role(request, ["supervisor"])
    return render(request, "supervisor.html")


@app.get("/admin-dashboard", response_class=HTMLResponse)
def admin_dashboard(request: Request):
    require_role(request, ["admin"])
    return render(request, "admin_dashboard.html")


# =========================
# ADMIN: CREATE USERS
# =========================
@app.get("/admin-create-user", response_class=HTMLResponse)
def admin_create_user_page(request: Request):
    require_role(request, ["admin"])
    return render(request, "admin_create_user.html")


@app.post("/admin-create-user")
def admin_create_user_submit(
    request: Request,
    db: Session = Depends(get_db),
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    profile_pic: UploadFile = File(None)
):
    require_role(request, ["admin"])

    role = (role or "").strip().lower()
    if role not in ["student", "supervisor", "admin"]:
        return render(request, "admin_create_user.html", {"error": "Invalid role selected."})

    email_clean = email.strip().lower()
    exists = db.query(User).filter(User.email == email_clean).first()
    if exists:
        return render(request, "admin_create_user.html", {"error": "Email already exists."})

    pic_url = ""
    try:
        if profile_pic and profile_pic.filename:
            pic_url = _save_profile_pic(profile_pic)
    except HTTPException as e:
        return render(request, "admin_create_user.html", {"error": e.detail})

    u = User(
        name=name.strip(),
        email=email_clean,
        password_hash=hash_password(password),
        role=role,
        profile_pic=pic_url
    )
    db.add(u)
    db.commit()

    return RedirectResponse("/admin-users", status_code=HTTP_302_FOUND)


# =========================
# ADMIN USERS LIST + DELETE
# =========================
@app.get("/admin-users", response_class=HTMLResponse)
def admin_users_list(request: Request, db: Session = Depends(get_db)):
    require_role(request, ["admin"])
    users = db.query(User).order_by(User.role.asc(), User.id.asc()).all()
    return render(request, "admin_users.html", {"users": users})


@app.post("/admin-user-delete/{user_id}")
def admin_user_delete(request: Request, user_id: int, db: Session = Depends(get_db)):
    require_role(request, ["admin"])

    me_email = current_user_email(request)
    me = db.query(User).filter(User.email == me_email).first()

    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")

    if me and u.id == me.id:
        return RedirectResponse("/admin-users", status_code=HTTP_302_FOUND)

    _delete_profile_pic_if_local(u.profile_pic or "")

    db.delete(u)
    db.commit()
    return RedirectResponse("/admin-users", status_code=HTTP_302_FOUND)


# =========================
# SUPERVISOR / ADMIN UPLOAD FLOW
# =========================
@app.get("/upload-report", response_class=HTMLResponse)
def upload_report_page(request: Request):
    require_role(request, ["supervisor", "admin"])
    return render(request, "upload_report.html")


@app.post("/upload-report-extract")
def upload_report_extract(
    request: Request,
    file: UploadFile = File(None),
    pdf_file: UploadFile = File(None)
):
    """
    Accepts BOTH field names:
    - file (your original backend)
    - pdf_file (nice frontend naming)
    """
    require_role(request, ["supervisor", "admin"])

    up = file or pdf_file
    if not up or not up.filename:
        return JSONResponse(status_code=400, content={"ok": False, "error": "No file uploaded."})

    if not up.filename.lower().endswith(".pdf"):
        return JSONResponse(status_code=400, content={"ok": False, "error": "Please upload a PDF file."})

    tmp_name = f"{int(time.time())}_{up.filename}"
    tmp_path = UPLOADS_DIR / tmp_name
    with open(tmp_path, "wb") as f:
        f.write(up.file.read())

    try:
        title, abstract = extract_title_and_abstract(tmp_path, tmp_name)
    except Exception as e:
        return JSONResponse(status_code=500, content={"ok": False, "error": str(e)})

    email = current_user_email(request)
    role = current_role(request)

    return {
        "ok": True,
        "filename": tmp_name,
        "title": title,
        "abstract": abstract,
        "uploaded_by": email or role,
        "status": "approved",
    }


# ✅ ALIAS: frontend can call /extract-meta too
@app.post("/extract-meta")
def extract_meta_alias(
    request: Request,
    file: UploadFile = File(None),
    pdf_file: UploadFile = File(None)
):
    return upload_report_extract(request=request, file=file, pdf_file=pdf_file)


@app.post("/upload-report-confirm")
def upload_report_confirm(
    request: Request,
    db: Session = Depends(get_db),
    file: UploadFile = File(None),
    pdf_file: UploadFile = File(None),
    title: str = Form(...),
    abstract: str = Form(...)
):
    """
    Accept BOTH file field names:
    - file
    - pdf_file
    """
    require_role(request, ["supervisor", "admin"])

    up = file or pdf_file
    if not up or not up.filename:
        raise HTTPException(status_code=400, detail="No PDF uploaded.")

    if not up.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="PDF only.")

    safe_name = f"{int(time.time())}_{up.filename}"
    save_path = UPLOADS_DIR / safe_name
    with open(save_path, "wb") as f:
        f.write(up.file.read())

    email = current_user_email(request)
    role = current_role(request)

    report = Report(
        title=title.strip(),
        abstract=abstract.strip(),
        filename=safe_name,
        file_path=str(save_path),
        uploaded_by=email or role,
        status="approved",
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    year = datetime.now().strftime("%Y")
    report.doc_no = f"FYP-{year}-{report.id:04d}"
    db.commit()

    return RedirectResponse("/supervisor-my-reports", status_code=HTTP_302_FOUND)


# ✅ NEW: Accept POST /upload-report too (so your form won’t 405 anymore)
@app.post("/upload-report")
def upload_report_post_alias(
    request: Request,
    db: Session = Depends(get_db),
    file: UploadFile = File(None),
    pdf_file: UploadFile = File(None),
    title: str = Form(...),
    abstract: str = Form(...)
):
    return upload_report_confirm(
        request=request,
        db=db,
        file=file,
        pdf_file=pdf_file,
        title=title,
        abstract=abstract
    )


@app.get("/supervisor-my-reports", response_class=HTMLResponse)
def supervisor_my_reports(request: Request, db: Session = Depends(get_db)):
    require_role(request, ["supervisor", "admin"])
    email = current_user_email(request)
    role = current_role(request)

    q = db.query(Report).order_by(Report.id.desc())
    if role == "supervisor":
        q = q.filter(Report.uploaded_by == email)
    reports = q.all()

    return render(request, "supervisor_my_reports.html", {"reports": reports})


@app.get("/report-download/{report_id}")
def report_download(request: Request, report_id: int, db: Session = Depends(get_db)):
    require_role(request, ["supervisor", "admin"])
    r = db.query(Report).filter(Report.id == report_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(path=r.file_path, filename=r.filename, media_type="application/pdf")


@app.get("/report-edit/{report_id}", response_class=HTMLResponse)
def report_edit_page(request: Request, report_id: int, db: Session = Depends(get_db)):
    require_role(request, ["supervisor", "admin"])
    r = db.query(Report).filter(Report.id == report_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")
    return render(request, "report_edit.html", {"report": r})


@app.post("/report-edit/{report_id}")
def report_edit_save(
    request: Request,
    report_id: int,
    db: Session = Depends(get_db),
    title: str = Form(...),
    abstract: str = Form(...)
):
    require_role(request, ["supervisor", "admin"])
    r = db.query(Report).filter(Report.id == report_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")
    r.title = title.strip()
    r.abstract = abstract.strip()
    db.commit()
    return RedirectResponse("/supervisor-my-reports", status_code=HTTP_302_FOUND)


@app.post("/report-delete/{report_id}")
def report_delete(request: Request, report_id: int, db: Session = Depends(get_db)):
    require_role(request, ["supervisor", "admin"])
    r = db.query(Report).filter(Report.id == report_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")

    try:
        if r.file_path and Path(r.file_path).exists():
            Path(r.file_path).unlink()
    except Exception:
        pass

    db.delete(r)
    db.commit()
    return RedirectResponse("/supervisor-my-reports", status_code=HTTP_302_FOUND)


# =========================
# STUDENT SEARCH + REQUEST
# =========================
DEFAULT_SUGGESTIONS = [
    "IoT smart monitoring system",
    "AI-based recommendation system",
    "Smart attendance system",
    "FYP repository security",
    "Document classification using NLP",
    "AI plagiarism detection",
    "Smart campus system",
    "Facial recognition access control",
]


def build_suggestions(db: Session, query: str) -> List[str]:
    suggestions = []
    titles = [r.title for r in db.query(Report).order_by(Report.id.desc()).limit(15).all()]
    for t in titles:
        words = [w for w in re.split(r"\W+", t) if len(w) > 3]
        if len(words) >= 2:
            s = " ".join(words[:5])
            if s and s.lower() not in [x.lower() for x in suggestions]:
                suggestions.append(s)

    if query:
        suggestions.insert(0, f"{query} system")
        suggestions.insert(0, f"{query} using AI")

    for d in DEFAULT_SUGGESTIONS:
        if d.lower() not in [x.lower() for x in suggestions]:
            suggestions.append(d)

    return suggestions[:12]


@app.get("/student-search", response_class=HTMLResponse)
def student_search_page(request: Request):
    require_role(request, ["student"])
    return render(request, "student_search.html")


@app.get("/student-search-results")
def student_search_results(request: Request, db: Session = Depends(get_db), query: str = ""):
    require_role(request, ["student"])
    q = (query or "").strip().lower()

    base = db.query(Report).filter(Report.status == "approved")

    results = []
    if q:
        rows = base.all()
        for r in rows:
            hay = f"{r.doc_no} {r.title} {r.abstract}".lower()
            if q in hay:
                results.append({"id": r.id, "doc_no": r.doc_no, "title": r.title, "abstract": r.abstract})
    else:
        rows = base.order_by(Report.id.desc()).limit(5).all()
        results = [{"id": r.id, "doc_no": r.doc_no, "title": r.title, "abstract": r.abstract} for r in rows]

    return {"results": results, "suggestions": build_suggestions(db, query)}


@app.get("/student-request/{report_id}", response_class=HTMLResponse)
def student_request_page(request: Request, report_id: int, db: Session = Depends(get_db)):
    require_role(request, ["student"])
    r = db.query(Report).filter(Report.id == report_id, Report.status == "approved").first()
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")
    template_name = "student_request.html" if (TEMPLATES_DIR / "student_request.html").exists() else "request_access.html"
    return render(request, template_name, {"report": r})


@app.post("/submit-request")
def submit_request(
    request: Request,
    db: Session = Depends(get_db),
    report_id: int = Form(...),
    student_name: str = Form(...),
    matric_no: str = Form(...),
    reason: str = Form(...)
):
    require_role(request, ["student"])

    r = db.query(Report).filter(Report.id == report_id, Report.status == "approved").first()
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")

    session_email = current_user_email(request)
    if not session_email:
        raise HTTPException(status_code=401, detail="Not logged in")

    exists = db.query(AccessRequest).filter(
        AccessRequest.report_id == report_id,
        AccessRequest.student_email == session_email
    ).first()
    if exists:
        return render(request, "request_success.html", {"message": "You already requested this report."})

    req = AccessRequest(
        report_id=report_id,
        student_name=student_name.strip(),
        matric_no=matric_no.strip(),
        student_email=session_email,
        reason=reason.strip(),
        status="pending"
    )
    db.add(req)
    db.commit()

    return render(request, "request_success.html", {"message": "Request submitted successfully."})


@app.get("/student-requests", response_class=HTMLResponse)
def student_requests_page(request: Request, db: Session = Depends(get_db)):
    require_role(request, ["student"])
    session_email = current_user_email(request)

    reqs = db.query(AccessRequest).filter(
        AccessRequest.student_email == session_email
    ).order_by(AccessRequest.id.desc()).all()

    rep_map = {r.id: r.title for r in db.query(Report).all()}
    return render(request, "student_requests.html", {"reqs": reqs, "reports": rep_map})


@app.get("/student-view-approved/{request_id}")
def student_view_approved(request: Request, request_id: int, db: Session = Depends(get_db)):
    require_role(request, ["student"])
    session_email = current_user_email(request)

    ar = db.query(AccessRequest).filter(AccessRequest.id == request_id).first()
    if not ar:
        raise HTTPException(status_code=404, detail="Request not found")
    if ar.student_email != session_email:
        raise HTTPException(status_code=403, detail="Forbidden")
    if ar.status != "approved":
        raise HTTPException(status_code=403, detail="Not approved")

    rep = db.query(Report).filter(Report.id == ar.report_id).first()
    if not rep:
        raise HTTPException(status_code=404, detail="Report not found")

    return FileResponse(path=rep.file_path, filename=rep.filename, media_type="application/pdf")


# =========================
# ADMIN REQUESTS (EMAIL)
# =========================
@app.get("/admin-requests", response_class=HTMLResponse)
def admin_requests_page(request: Request, db: Session = Depends(get_db)):
    require_role(request, ["admin"])

    reqs = db.query(AccessRequest).order_by(AccessRequest.id.desc()).all()
    report_titles = {r.id: r.title for r in db.query(Report).all()}

    return render(request, "admin_requests.html", {
        "requests": [
            {
                "id": r.id,
                "report_id": r.report_id,
                "report_title": report_titles.get(r.report_id, ""),
                "student_name": r.student_name,
                "matric_no": r.matric_no,
                "email": r.student_email,
                "reason": r.reason,
                "status": r.status
            } for r in reqs
        ]
    })


@app.post("/admin-approve/{req_id}")
def admin_approve(request: Request, req_id: int, db: Session = Depends(get_db)):
    require_role(request, ["admin"])

    ar = db.query(AccessRequest).filter(AccessRequest.id == req_id).first()
    if not ar:
        raise HTTPException(status_code=404, detail="Request not found")

    ar.status = "approved"
    ar.reviewed_by = current_user_email(request)
    ar.reviewed_at = datetime.utcnow()
    db.commit()

    # ✅ Recommended: neutral subject reduces spam
    send_status_email(
        ar.student_email,
        "Unisel FYP Repository: Request Update",
        "Your request has been APPROVED.\n\nPlease log in to view/download the report.\n\nThank you."
    )

    return RedirectResponse("/admin-requests", status_code=HTTP_302_FOUND)


@app.post("/admin-reject/{req_id}")
def admin_reject(request: Request, req_id: int, db: Session = Depends(get_db)):
    require_role(request, ["admin"])

    ar = db.query(AccessRequest).filter(AccessRequest.id == req_id).first()
    if not ar:
        raise HTTPException(status_code=404, detail="Request not found")

    ar.status = "rejected"
    ar.reviewed_by = current_user_email(request)
    ar.reviewed_at = datetime.utcnow()
    db.commit()

    send_status_email(
        ar.student_email,
        "Unisel FYP Repository: Request Update",
        "Your request has been reviewed.\n\nStatus: REJECTED\n\nIf you have further enquiries, kindly email us.\n\nThank you."
    )

    return RedirectResponse("/admin-requests", status_code=HTTP_302_FOUND)


# =========================
# STAFF SEARCH
# =========================
@app.get("/staff-search", response_class=HTMLResponse)
def staff_search_page(request: Request):
    require_role(request, ["supervisor", "admin"])
    return render(request, "staff_search.html")


@app.get("/staff-search-results")
def staff_search_results(request: Request, db: Session = Depends(get_db), query: str = ""):
    require_role(request, ["supervisor", "admin"])
    q = (query or "").strip().lower()
    rows = db.query(Report).order_by(Report.id.desc()).all()

    out = []
    for r in rows:
        hay = f"{r.doc_no} {r.title} {r.abstract} {r.uploaded_by}".lower()
        if (not q) or (q in hay):
            out.append({
                "id": r.id,
                "doc_no": r.doc_no,
                "title": r.title,
                "abstract": r.abstract,
                "uploaded_by": r.uploaded_by
            })
    return {"results": out}


@app.get("/staff-view/{report_id}")
def staff_view_full_pdf(request: Request, report_id: int, db: Session = Depends(get_db)):
    require_role(request, ["supervisor", "admin"])
    r = db.query(Report).filter(Report.id == report_id).first()
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(path=r.file_path, filename=r.filename, media_type="application/pdf")
