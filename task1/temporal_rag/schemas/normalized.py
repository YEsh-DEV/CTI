from datetime import date, datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class IOC(BaseModel):
    category: str
    type: str
    value: str
    comment: Optional[str] = ""

    model_config = ConfigDict(extra="ignore")


class NormalizedCTIEvent(BaseModel):
    id: str = Field(description="Composite unique identifier e.g. '2019_1976'")
    year: int = Field(description="Dataset release year")
    event_id: int = Field(description="Raw event ID within the year file pair")
    date: date
    info_title: str
    iocs: List[IOC] = Field(default_factory=list)
    source_files: List[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="ignore")


class NormalizedCVE(BaseModel):
    cve_id: str
    date_published: datetime
    date_public: Optional[datetime] = None
    title: Optional[str] = None
    description: str
    cwe_id: Optional[str] = None
    cwe_description: Optional[str] = None
    affected_vendor: Optional[str] = None
    affected_product: Optional[str] = None
    affected_versions: List[str] = Field(default_factory=list)
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    cvss_vector: Optional[str] = None
    cvss_version: str = "none"  # "3.1" or "4.0" or "none"
    references: List[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="ignore")
