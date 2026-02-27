"""
Audit Logging System for Authentication & Authorization Service

Tracks critical events: login, logout, registration, password changes, role/group modifications.
All events logged as structured JSON for easy analysis and compliance.

Event Types:
- LOGIN_SUCCESS: User successfully authenticated
- LOGIN_FAILURE: Failed login attempt
- LOGOUT: User logged out
- TOKEN_REFRESH: Access token refreshed
- REGISTRATION: New user registered
- PASSWORD_CHANGED: User changed password
- PASSWORD_RESET: Password reset via recovery
- USER_CREATED: Admin created user
- USER_DELETED: Admin deleted user
- ROLE_ASSIGNED: Role assigned to user
- ROLE_REVOKED: Role removed from user
- SESSION_REVOKED: User session terminated
"""

import json
import logging
from datetime import datetime
from typing import Optional
from enum import Enum
from fastapi import Request


class AuditEventType(str, Enum):
    ""Enumeration of audit event types""
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    LOGOUT = "LOGOUT"
    TOKEN_REFRESH = "TOKEN_REFRESH"
    REGISTRATION = "REGISTRATION"
    PASSWORD_CHANGED = "PASSWORD_CHANGED"
    PASSWORD_RESET = "PASSWORD_RESET"
    USER_CREATED = "USER_CREATED"
    USER_DELETED = "USER_DELETED"
    ROLE_ASSIGNED = "ROLE_ASSIGNED"
    ROLE_REVOKED = "ROLE_REVOKED"
    SESSION_REVOKED = "SESSION_REVOKED"
    UNAUTHORIZED_ACCESS = "UNAUTHORIZED_ACCESS"


class AuditLogger:
    ""Structured audit logger for security events""
    
    def __init__(self, logger_name: str = "auth.audit"):
        self.logger = logging.getLogger(logger_name)
    
    def log_event(
        self,
        event_type: AuditEventType,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[dict] = None,
        correlation_id: Optional[str] = None,
        status_code: Optional[int] = None,
    ):
        ""
        Log an audit event with structured JSON format.
        ""
        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": event_type.value,
            "user_id": user_id,
            "username": username,
            "ip_address": ip_address,
            "correlation_id": correlation_id,
            "status_code": status_code,
            "details": details or {},
        }
        
        self.logger.info(json.dumps(event))
    
    def log_login_success(
        self,
        user_id: str,
        username: str,
        ip_address: str,
        realm: str = "demo",
        correlation_id: Optional[str] = None,
    ):
        self.log_event(
            event_type=AuditEventType.LOGIN_SUCCESS,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            correlation_id=correlation_id,
            details={"realm": realm},
        )
    
    def log_registration(
        self,
        user_id: str,
        username: str,
        email: str,
        ip_address: str,
        correlation_id: Optional[str] = None,
    ):
        self.log_event(
            event_type=AuditEventType.REGISTRATION,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            correlation_id=correlation_id,
            details={"email": email},
        )
    
    def log_password_changed(
        self,
        user_id: str,
        username: str,
        ip_address: str,
        correlation_id: Optional[str] = None,
    ):
        self.log_event(
            event_type=AuditEventType.PASSWORD_CHANGED,
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            correlation_id=correlation_id,
        )
    
    def log_event(
        self,
        event_type: AuditEventType,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[dict] = None,
        correlation_id: Optional[str] = None,
        status_code: Optional[int] = None,
    ):
        event = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": event_type.value,
            "user_id": user_id,
            "username": username,
            "ip_address": ip_address,
            "correlation_id": correlation_id,
            "status_code": status_code,
            "details": details or {},
        }
        
        self.logger.info(json.dumps(event))


audit_logger = AuditLogger()


def get_client_ip(request: Request) -> str:
    ""Extract client IP address from request""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    
    return request.client.host if request.client else "unknown"
