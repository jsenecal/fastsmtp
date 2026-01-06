"""Main API router combining all endpoints."""

from fastapi import APIRouter

from fastsmtp.api import auth, domains, operations, recipients, rules, users

api_router = APIRouter(prefix="/api/v1")

# Include all routers
api_router.include_router(operations.router)
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(domains.router)
api_router.include_router(recipients.router)
api_router.include_router(rules.router)
