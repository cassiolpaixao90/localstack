import secrets
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class UserImportJob:
    job_id: str
    job_name: str
    pool_id: str
    pool_name: str
    cloudwatch_logs_role_arn: str
    status: str
    creation_date: datetime
    presigned_url: str
    upload_expires_at: datetime
    upload_nonce: str
    role_identity: str
    password_hashing_algorithm: str | None = None
    start_date: datetime | None = None
    completion_date: datetime | None = None
    imported_users: int = 0
    skipped_users: int = 0
    failed_users: int = 0
    completion_message: str | None = None
    uploaded_at: datetime | None = None
    uploaded_size: int = 0
    uploaded_sha256: str | None = None
    upload_in_progress: bool = False
    log_events: list[dict[str, int | str]] = field(default_factory=list)
    dropped_log_events: int = 0


@dataclass
class UserImportState:
    version: int = 1
    signing_secret: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    jobs: dict[str, UserImportJob] = field(default_factory=dict)
