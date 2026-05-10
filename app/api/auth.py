from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional
from app.database import get_db
from app.iam.manager import IAMManager
from app.iam.policy import PolicyEngine
from app.audit.logger import AuditLogger

router = APIRouter(prefix="/auth", tags=["authentication"])
security = HTTPBearer()

class UserRegisterRequest(BaseModel):
    username: str
    password: str
    email: Optional[str] = None

class UserRegisterResponse(BaseModel):
    id: str
    username: str
    email: Optional[str]

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class AssignRoleRequest(BaseModel):
    username: str
    role_name: str

class AssignRoleResponse(BaseModel):
    message: str

iam_manager = IAMManager()

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security),
                     db: Session = Depends(get_db)):
    token = credentials.credentials
    payload = iam_manager.verify_token(token)

    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    from app.models.user import User
    user = db.query(User).filter(User.id == payload["sub"]).first()

    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "roles": payload.get("roles", [])
    }

@router.post("/register", response_model=UserRegisterResponse)
def register(request: UserRegisterRequest, db: Session = Depends(get_db)):
    try:
        user = iam_manager.create_user(db, request.username, request.password, request.email)
        return UserRegisterResponse(**user)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/login", response_model=LoginResponse)
def login(request: LoginRequest, req: Request, db: Session = Depends(get_db)):
    token = iam_manager.authenticate(db, request.username, request.password)
    if not token:
        AuditLogger.log(
            user_id=None,
            action="LOGIN_FAIL",
            resource="auth",
            resource_id=request.username,
            success=False,
            details={"reason": "invalid_credentials"},
            source_ip=req.client.host,
        )
        raise HTTPException(status_code=401, detail="Invalid username or password")

    AuditLogger.log(
        user_id=request.username,
        action="LOGIN",
        resource="auth",
        resource_id=request.username,
        success=True,
        details={},
        source_ip=req.client.host,
    )
    return LoginResponse(access_token=token, expires_in=60 * 60)

@router.post("/assign-role", response_model=AssignRoleResponse)
def assign_role(request: AssignRoleRequest, req: Request,
                current_user: dict = Depends(get_current_user),
                db: Session = Depends(get_db)):
    if "admin" not in current_user.get("roles", []):
        AuditLogger.log(
            user_id=current_user.get("id"),
            action="ROLE_ASSIGN",
            resource="role",
            resource_id=request.role_name,
            success=False,
            details={
                "reason": "insufficient_role",
                "target_user": request.username,
                "required_role": "admin",
                "roles": current_user.get("roles", []),
            },
            source_ip=req.client.host,
        )
        raise HTTPException(status_code=403, detail="Admin role required")

    try:
        iam_manager.assign_role(db, request.username, request.role_name)
        AuditLogger.log(
            user_id=current_user.get("id"),
            action="ROLE_ASSIGN",
            resource="role",
            resource_id=request.role_name,
            success=True,
            details={"target_user": request.username},
            source_ip=req.client.host,
        )
        return AssignRoleResponse(message=f"Role '{request.role_name}' assigned to '{request.username}'")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
