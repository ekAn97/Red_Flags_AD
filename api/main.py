from fastapi import FastAPI, HTTPException, Query, Header, Depends, Request
from fastapi.responses import JSONResponse
from typing import Optional, List
from datetime import datetime, timedelta
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import os

from database import db

app = FastAPI(
    title = "Red Flags API",
    description = "REST API for querying security incidents detected by the detection tool",
    version = "1.0.0",
    docs_url = "/docs",
    redoc_url = "/redoc"
)

# Limit request rate
limiter = Limiter(key_func = get_remote_address)
app.state.Limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# API key authentication
API_KEY = os.getenv("API_KEY", None)

def verify_api_key(x_api_key):
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code = 401, detail = "Invalid or missing API key")
    return True

@app.get("/")
@limiter.limit("100/minute")
async def root(request):
    return {
        "service": "Red Flags API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
        "endpoints": {
            "incidents": "/incidents",
            "statistics": "/statistics"
        }
    }

@app.get("/incidents")
@limiter.limit("100/minute")
async def list_incidents(
    request: Request,
    limit: int = Query(20, ge=1, le=100, description="Number of results (max 100)"),
    offset: int = Query(0, ge=0, description = "Skip N results (pagination)"),
    severity: Optional[str] = Query(None, description = "Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)"),
    log_type: Optional[str] = Query(None, description="Filter by log type (system, web, application)"),
    source_host: Optional[str] = Query(None, description="Filter by source host"),
    hours: Optional[int] = Query(None, description="Last N hours (e.g., 24)"),
    authenticated: bool = Depends(verify_api_key)
):
    try:
        # Date range if hours is provided
        date_from = None
        if hours:
            date_from = datetime.now() - timedelta(hours=hours)

        incidents = db.get_incidents(
            limit = limit,
            offset = offset,
            severity = severity,
            log_type = log_type,
            source_host = source_host,
            date_from = date_from
        )

        return {
            "total_returned": len(incidents),
            "limit": limit,
            "offset": offset,
            "filters": {
                "severity": severity,
                "log_type": log_type,
                "source_host": source_host,
                "hours": hours
            },
            "incidents": incidents
        }
    except Exception as e:
        raise HTTPException(status_code = 500, detail = f"Database error: {str(e)}")
    
@app.get("/incidents/{incident_id}")
@limiter.limit("100/minute")
async def get_incident(
    request: Request,
    incident_id: int,
    authenticated: bool = Depends(verify_api_key)
):
    try:
        incident = db.get_single_incident(incident_id)

        if not incident:
            raise HTTPException(status_code = 404, detail = f"Database error: {str(e)}")

        return incident

    except HTTPException:
        raise
    except Exception as e:  # ← Missing except block!
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
        
@app.get("/statistics")
@limiter.limit("100/minute")
async def get_statistics(
    request: Request,
    authenticated: bool = Depends(verify_api_key)
):
    try:
        stats = db.get_stats()
        return stats
    except Exception as e:
        raise HTTPException(status_code = 500, detail = f"Database error: {str(e)}")
    

@app.get("/search/ip/{ip_address}")
@limiter.limit("100/minute")
async def search_by_ip(
    request: Request,
    ip_address: str,
    authenticated: bool = Depends(verify_api_key)
):
    try:
        incidents = db.search_by_ip(ip_address)

        return {
            "ip_address": ip_address,
            "total_found": len(incidents),
            "incidents": incidents
        }
    except Exception as e:
        raise HTTPException(status_code = 500, detail = f"Database error: {str(e)}")
    
@app.get("/recent")
@limiter.limit("100/minute")
async def get_recent_incidents(
    request: Request,
    hours: int = Query(24, ge=1, le=168, description = "Number of hours to look back (max 168 = 1 week)"),
    authenticated: bool = Depends(verify_api_key)
):
    try:
        incidents = db.get_recent(hours = hours)

        return {
            "hours": hours,
            "total_found": len(incidents),
            "incidents": incidents
        }
    except Exception as e:
        raise HTTPException(status_code = 500, detail = f"Database error: {str(e)}")
    
@app.on_event("shutdown")
async def shutdown_event():
    db.close()

# Run with: uvicorn main:app --host 0.0.0.0 --port 8000


