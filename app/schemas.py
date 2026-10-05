from typing import List, Optional
from pydantic import BaseModel, Field


class IngestionPayload(BaseModel):
    endpoint: str
    http_method: str
    payload: str
    user_agent: Optional[str] = None


class OllamaAuditResponse(BaseModel):
    threat_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Threat rating scale from 0 (safe) to 100 (critical)",
    )
    flagged_categories: List[str] = Field(
        ..., description="Detected categories such as sql_injection, xss, pii_leak, safe"
    )
    remediation_action: str = Field(
        ..., description="Recommended action: ALLOW, SANITIZE, or BLOCK"
    )


class AuditRecord(BaseModel):
    telemetry_id: int
    payload_sample: str
    threat_score: int
    flagged_categories: str
    remediation_action: str
    inspection_time_ms: float
    raw_llm_output: Optional[str] = None