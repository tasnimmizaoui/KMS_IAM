from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api import auth_router, keys_router
from app.api.audit import router as audit_router


app = FastAPI(
    title="KMS with Mini-IAM",
    description="Cryptographic Key Management System with Identity & Access Management",
    version="1.0.0"
)

# CORS middleware for web clients
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router)
app.include_router(keys_router)
app.include_router(audit_router)


@app.get("/")
def root():
    return {"message": "KMS-IAM API", "status": "running"}

@app.get("/health")
def health():
    return {"status": "healthy"}