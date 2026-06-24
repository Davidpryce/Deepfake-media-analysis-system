"""
Main FastAPI application with all core modules
"""

from fastapi import FastAPI
from contextlib import asynccontextmanager
import logging

from app.core.config import settings
from app.core.database import DatabaseManager
from app.core.redis import init_redis, close_redis
from app.core.security import setup_security
from app.api import setup_api_routes

logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    
    # Initialize database
    DatabaseManager.init_db()
    logger.info("Database initialized")
    
    # Initialize Redis
    await init_redis()
    logger.info("Redis initialized")
    
    yield
    
    # Shutdown
    await close_redis()
    logger.info("Application shutdown complete")

# Create app
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Production Deepfake Forensic Analysis System",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# Setup security
setup_security(app)

# Setup API routes
setup_api_routes(app)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower()
    )