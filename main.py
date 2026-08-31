from fastapi import FastAPI, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from app.auth.register import router as register_router
from app.auth.login import router as login_router
from app.auth.dependencies import get_current_user, require_admin
from app.targets.routes import router as targets_router
from app.scanners.routes import router as scanners_router
from app.findings_routes import router as findings_router
from app.reports.routes import router as reports_router


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="AI-Assisted VAPT Platform",
    description="Automated Vulnerability Assessment and Penetration Testing Platform",
    version="1.0.0"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# AUTHENTICATION
# ============================================================

app.include_router(register_router)
app.include_router(login_router)


# ============================================================
# AUTH TEST
# ============================================================

@app.get("/protected")
def protected(
    current_user=Depends(get_current_user)
):
    return {
        "message": "You are authenticated",
        "username": current_user.get("sub"),
        "role": current_user.get("role")
    }


# ============================================================
# ADMIN TEST
# ============================================================

@app.get("/admin-only")
def admin_only(
    current_user=Depends(require_admin)
):
    return {
        "message": "Welcome Admin",
        "username": current_user.get("sub"),
        "role": current_user.get("role")
    }


# ============================================================
# TARGET ROUTES
# ============================================================

app.include_router(targets_router)


# ============================================================
# SCANNER ROUTES
# ============================================================

app.include_router(scanners_router)


# ============================================================
# FINDINGS ROUTES
# ============================================================

app.include_router(findings_router)


# ============================================================
# REPORT ROUTES
# ============================================================

app.include_router(reports_router)

# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():
    return {
        "message": "AI-Assisted VAPT Platform is running"
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }


# ============================================================
# LOGIN PAGE
# ============================================================

@app.get(
    "/login.html",
    include_in_schema=False
)
def login_page():
    return FileResponse(
        "frontend/login.html"
    )


# ============================================================
# DASHBOARD
# ============================================================

app.mount(
    "/dashboard",
    StaticFiles(
        directory="frontend",
        html=True
    ),
    name="dashboard"
)

