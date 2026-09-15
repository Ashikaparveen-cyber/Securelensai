"""
SecureLens AI — FastAPI Application Entrypoint
"""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from database.db import init_db
from routers import scan, ai, reports, auth


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize DB (MongoDB Atlas or SQLite fallback)
    await init_db()
    yield


app = FastAPI(
    title="SecureLens AI API",
    description="Automated Cybersecurity Scanning & Groq AI Vulnerability Analyst Platform",
    version="2.0.0",
    lifespan=lifespan,
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(auth.router)
app.include_router(scan.router)
app.include_router(ai.router)
app.include_router(reports.router)


@app.get("/api/health")
async def health_check():
    return {"status": "online", "service": "SecureLens AI Backend", "version": "2.0.0"}


# Serve frontend static assets if directory exists
frontend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "frontend"))
if os.path.exists(frontend_path):
    app.mount("/static", StaticFiles(directory=frontend_path), name="static")

    @app.get("/")
    async def serve_index():
        return FileResponse(os.path.join(frontend_path, "index.html"))

    @app.get("/dashboard")
    @app.get("/dashboard.html")
    async def serve_dashboard():
        return FileResponse(os.path.join(frontend_path, "dashboard.html"))

    @app.get("/css/{filename}")
    async def serve_css(filename: str):
        css_file = os.path.join(frontend_path, "css", filename)
        if os.path.exists(css_file):
            return FileResponse(css_file, media_type="text/css")
        return JSONResponse(status_code=404, content={"error": "CSS file not found"})

    @app.get("/js/{filename}")
    async def serve_js(filename: str):
        js_file = os.path.join(frontend_path, "js", filename)
        if os.path.exists(js_file):
            return FileResponse(js_file, media_type="application/javascript")
        return JSONResponse(status_code=404, content={"error": "JS file not found"})

    @app.get("/assets/{filename}")
    async def serve_assets(filename: str):
        asset_file = os.path.join(frontend_path, "assets", filename)
        if os.path.exists(asset_file):
            return FileResponse(asset_file)
        return JSONResponse(status_code=404, content={"error": "Asset not found"})


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
