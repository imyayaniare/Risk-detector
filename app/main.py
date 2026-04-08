from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.analyzers.c_cpp import analyze_c_cpp
from app.analyzers.python_risks import analyze_python
from app.models import AnalyzeRequest, AnalyzeResponse, Language
from app.report import render_html_report

app = FastAPI(title="DetectionApp", version="0.1.0")

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(request, "index.html")


@app.post("/analyze")
def analyze(req: AnalyzeRequest) -> JSONResponse:
    if req.language in (Language.c, Language.cpp):
        findings = analyze_c_cpp(req.code, "c" if req.language == Language.c else "cpp")
    else:
        findings = analyze_python(req.code)

    resp = AnalyzeResponse(language=req.language, findings=findings, html_report="")
    resp.html_report = render_html_report(resp)
    return JSONResponse(resp.model_dump())


@app.post("/report", response_class=HTMLResponse)
def report(req: AnalyzeRequest) -> HTMLResponse:
    # Endpoint pratique si on veut afficher directement le rapport HTML dans un nouvel onglet.
    if req.language in (Language.c, Language.cpp):
        findings = analyze_c_cpp(req.code, "c" if req.language == Language.c else "cpp")
    else:
        findings = analyze_python(req.code)
    resp = AnalyzeResponse(language=req.language, findings=findings, html_report="")
    html_report = render_html_report(resp)
    return HTMLResponse(content=html_report)

