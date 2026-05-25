from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dataclasses import asdict, is_dataclass
from typing import Any

from d3fender.assessors.mainAssessor import runAssessment
import io
from fastapi import UploadFile, File

app = FastAPI(
    title="D3FENDer Assessment API",
    description="Threat-driven defensive capability gap assessment API",
    version="0.1.0",
    debug=True,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8080",
        "https://d3fender.up.railway.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class TextAssessmentRequest(BaseModel):
    content: str = Field(..., min_length=10)


class AssessmentResponse(BaseModel):
    input_type: str
    findings_count: int
    findings: list[Any]


def serialize_finding(obj: Any) -> Any:
    if is_dataclass(obj):
        return asdict(obj)

    if hasattr(obj, "dict"):
        return obj.dict()

    if hasattr(obj, "__dict__"):
        return obj.__dict__

    return str(obj)


@app.get("/")
def root():
    return {
        "service": "D3FENDer Assessment API",
        "status": "running"
    }


@app.get("/health")
def health():
    return {
        "status": "ok"
    }


@app.post("/api/assess/text", response_model=AssessmentResponse)
def assess_text(request: TextAssessmentRequest):
    try:
        findings = runAssessment("text", request.content)

        serialized_findings = [
            serialize_finding(finding)
            for finding in findings
        ]

        return AssessmentResponse(
            input_type="text",
            findings_count=len(serialized_findings),
            findings=serialized_findings
        )

    except Exception as ex:
        raise HTTPException(
            status_code=500,
            detail=f"Assessment failed: {str(ex)}"
        )

class JsonAssessmentRequest(BaseModel):
    content: str = Field(..., min_length=2)


class QuestionnaireAssessmentRequest(BaseModel):
    answers: dict[str, bool]

@app.post("/api/assess/json", response_model=AssessmentResponse)
def assess_json(request: JsonAssessmentRequest):
    try:
        findings = runAssessment("json", request.content)

        serialized_findings = [
            serialize_finding(finding)
            for finding in findings
        ]

        return AssessmentResponse(
            input_type="json",
            findings_count=len(serialized_findings),
            findings=serialized_findings
        )

    except Exception as ex:
        raise HTTPException(
            status_code=500,
            detail=f"JSON assessment failed: {str(ex)}"
        )


@app.post("/api/assess/questionnaire", response_model=AssessmentResponse)
def assess_questionnaire(request: QuestionnaireAssessmentRequest):
    try:
        findings = runAssessment("questionnaire", request.answers)

        serialized_findings = [
            serialize_finding(finding)
            for finding in findings
        ]

        return AssessmentResponse(
            input_type="questionnaire",
            findings_count=len(serialized_findings),
            findings=serialized_findings
        )

    except Exception as ex:
        raise HTTPException(
            status_code=500,
            detail=f"Questionnaire assessment failed: {str(ex)}"
        )

from d3fender.input.registry_loader import load_capability_registry, load_controls_registry


@app.get("/api/questionnaire")
def get_questionnaire():
    capabilities_registry = load_capability_registry()
    controls_registry = load_controls_registry()

    threat_context = []
    defensive_capabilities = []
    security_controls = []

    for capability in capabilities_registry.get("capabilities", []):
        question = {
            "id": capability["id"],
            "title": capability.get("title", capability["id"]),
            "category": capability.get("category", "general"),
            "text": capability.get(
                "interactive_text",
                f"Does your organization use {capability.get('title', capability['id'])}?"
            )
        }

        if capability.get("category") == "context":
            threat_context.append(question)
        else:
            defensive_capabilities.append(question)

    for control in controls_registry.get("controls", []):
        security_controls.append({
            "id": control["id"],
            "title": control.get("title", control["id"]),
            "category": control.get("category", "general"),
            "text": control.get(
                "interactive_text",
                f"Does your organization use {control.get('title', control['id'])}?"
            )
        })

    return {
        "threat_context": threat_context,
        "security_controls": security_controls,
        "defensive_capabilities": defensive_capabilities
    }

@app.post("/api/sbom/analyze")
async def analyze_sbom_file(file: UploadFile = File(...)):
    try:
        if not file.filename or not file.filename.endswith(".json"):
            raise HTTPException(
                status_code=400,
                detail="Only JSON SBOM files are supported."
            )

        content = await file.read()
        text_content = content.decode("utf-8")

        from d3fender.sbom_analysis.sbom_analyzer import (
            analyze_sbom,
            find_components_vulnerabilities
        )

        file_like = io.StringIO(text_content)

        components = analyze_sbom(file_like)
        vulnerabilities = find_components_vulnerabilities(components)

        return {
            "filename": file.filename,
            "components_count": len(components),
            "total_vulnerabilities_count": sum(len(vulns) for vulns in vulnerabilities.values()),
            "vulnerable_components_count": len(vulnerabilities),
            "components": [
                serialize_component(component)
                for component in components
            ],
            "vulnerabilities": {
                bom_ref: [
                    serialize_vulnerability(vuln)
                    for vuln in vulns
                ]
                for bom_ref, vulns in vulnerabilities.items()
            }
        }

    except HTTPException:
        raise

    except Exception as ex:
        import traceback
        traceback.print_exc()

        raise HTTPException(
            status_code=500,
            detail=f"SBOM analysis failed: {type(ex).__name__}: {str(ex)}"
        )

from dataclasses import asdict, is_dataclass


def serialize_component(component):
    if is_dataclass(component):
        return asdict(component)

    if hasattr(component, "__dict__"):
        return component.__dict__

    return str(component)


def serialize_vulnerability(vuln):
    return {
        "vulnerability_id": vuln.vulnerability_id,
        "aliases": vuln.aliases,
        "summary": vuln.summary,
        "details": vuln.details,
        "severity": vuln.severity,
        "references": vuln.references,
        "component": serialize_component(vuln.component)
    }

