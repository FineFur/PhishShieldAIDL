"""
PhishShield AI - Pydantic Schemas

Request and response models for the FastAPI backend.
"""

from pydantic import BaseModel, Field
from typing import Dict, Optional, List


class PredictRequest(BaseModel):
    """Request schema for URL prediction."""
    url: str = Field(
        ...,
        description="The URL to analyze for phishing detection",
        examples=["https://example.com"],
    )


class FeatureValues(BaseModel):
    """Extracted URL features."""
    url_length: int
    has_ip_address: int
    dot_count: int
    https_flag: int
    url_entropy: float
    token_count: int
    subdomain_count: float
    query_param_count: int
    tld_length: int
    path_length: int
    has_hyphen_in_domain: int
    number_of_digits: int
    tld_popularity: int
    suspicious_file_extension: int
    domain_name_length: int
    percentage_numeric_chars: float


class PredictResponse(BaseModel):
    """Response schema for URL prediction."""
    url: str = Field(..., description="The analyzed URL")
    verdict: str = Field(..., description="Phishing or Legitimate")
    phishing_probability: float = Field(
        ..., description="Model's phishing probability (0-1)"
    )
    legitimate_probability: float = Field(
        ..., description="1 - phishing_probability"
    )
    risk_level: str = Field(..., description="Low, Medium, or High")
    recommendation: str = Field(
        ..., description="Human-readable risk assessment"
    )
    features: Dict = Field(
        ..., description="Extracted URL feature values"
    )


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    model_loaded: bool


class ModelInfoResponse(BaseModel):
    """Model information response."""
    model_name: str
    feature_count: int
    features: List[str]
    model_type: str
    framework: str
    training_metrics: Optional[Dict] = None


class ErrorResponse(BaseModel):
    """Error response."""
    detail: str
