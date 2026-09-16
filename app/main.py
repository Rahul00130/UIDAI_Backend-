from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    Request
)

from fastapi.exceptions import RequestValidationError

from fastapi.responses import JSONResponse

from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    DateTime
)

from sqlalchemy.orm import Session

from sqlalchemy.sql import func

from pydantic import (
    BaseModel,
    EmailStr,
    Field,
    field_validator
)

import re

from app.database import (
    Base,
    engine,
    get_db
)

from app.auth import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user
)

from app.verification import (
    perform_demo_verification
)

from app.ai.analyzer import (
    analyze_verification
)


# =========================================================
# USER DATABASE MODEL
# =========================================================

class User(Base):

    __tablename__ = "users"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    name = Column(
        String,
        nullable=False
    )

    email = Column(
        String,
        unique=True,
        nullable=False,
        index=True
    )

    phone = Column(
        String,
        unique=True,
        nullable=False
    )

    password = Column(
        String,
        nullable=False
    )

    created_at = Column(
        DateTime,
        server_default=func.now()
    )

    is_active = Column(
        Boolean,
        default=True
    )


# =========================================================
# VERIFICATION DATABASE MODEL
# =========================================================

class Verification(Base):

    __tablename__ = "verifications"

    id = Column(
        Integer,
        primary_key=True,
        index=True
    )

    user_id = Column(
        Integer,
        nullable=False,
        index=True
    )

    aadhaar_hash = Column(
        String,
        nullable=False,
        index=True
    )

    masked_aadhaar = Column(
        String,
        nullable=False
    )

    name = Column(
        String,
        nullable=False
    )

    date_of_birth = Column(
        String,
        nullable=False
    )

    status = Column(
        String,
        nullable=False
    )

    message = Column(
        String,
        nullable=False
    )

    ai_score = Column(
        Integer,
        nullable=False
    )

    risk_level = Column(
        String,
        nullable=False
    )

    created_at = Column(
        DateTime,
        server_default=func.now()
    )


# =========================================================
# CREATE DATABASE TABLES
# =========================================================

Base.metadata.create_all(
    bind=engine
)


# =========================================================
# FASTAPI APPLICATION
# =========================================================

app = FastAPI(
    title="UIDAI Backend API",
    description="Backend API for UIDAI project",
    version="1.0.0"
)


# =========================================================
# GLOBAL VALIDATION ERROR HANDLER
# =========================================================

@app.exception_handler(
    RequestValidationError
)
async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError
):

    errors = []

    for error in exc.errors():

        field = ".".join(
            str(location)
            for location in error["loc"]
        )

        errors.append({
            "field": field,
            "message": error["msg"]
        })

    first_message = (
        errors[0]["message"]
        if errors
        else "Invalid request data"
    )

    return JSONResponse(

        status_code=422,

        content={
            "success": False,
            "error": "Validation Error",
            "message": first_message,
            "status_code": 422,
            "details": errors
        }
    )


# =========================================================
# GLOBAL HTTP ERROR HANDLER
# =========================================================

@app.exception_handler(
    HTTPException
)
async def http_exception_handler(
    request: Request,
    exc: HTTPException
):

    return JSONResponse(

        status_code=exc.status_code,

        content={
            "success": False,
            "error": "Request Error",
            "message": str(exc.detail),
            "status_code": exc.status_code
        }
    )


# =========================================================
# GLOBAL SERVER ERROR HANDLER
# =========================================================

@app.exception_handler(
    Exception
)
async def general_exception_handler(
    request: Request,
    exc: Exception
):

    return JSONResponse(

        status_code=500,

        content={
            "success": False,
            "error": "Internal Server Error",
            "message": "Something went wrong on the server",
            "status_code": 500
        }
    )


# =========================================================
# VALIDATION HELPERS
# =========================================================

def validate_name(value: str):

    value = value.strip()

    if len(value) < 2:

        raise ValueError(
            "Name must contain at least 2 characters"
        )

    if len(value) > 100:

        raise ValueError(
            "Name cannot exceed 100 characters"
        )

    if not re.fullmatch(
        r"[A-Za-z ]+",
        value
    ):

        raise ValueError(
            "Name can contain only letters and spaces"
        )

    return value


def validate_phone(value: str):

    value = value.strip()

    if not re.fullmatch(
        r"[6-9][0-9]{9}",
        value
    ):

        raise ValueError(
            "Phone number must contain 10 digits and start with 6-9"
        )

    return value


def validate_password(value: str):

    if len(value) < 8:

        raise ValueError(
            "Password must contain at least 8 characters"
        )

    if not re.search(
        r"[A-Z]",
        value
    ):

        raise ValueError(
            "Password must contain at least one uppercase letter"
        )

    if not re.search(
        r"[a-z]",
        value
    ):

        raise ValueError(
            "Password must contain at least one lowercase letter"
        )

    if not re.search(
        r"[0-9]",
        value
    ):

        raise ValueError(
            "Password must contain at least one number"
        )

    return value


# =========================================================
# REQUEST MODELS
# =========================================================

class UserCreate(BaseModel):

    name: str = Field(
        min_length=2,
        max_length=100
    )

    email: EmailStr

    phone: str

    password: str

    @field_validator("name")
    @classmethod
    def check_name(cls, value):

        return validate_name(value)

    @field_validator("phone")
    @classmethod
    def check_phone(cls, value):

        return validate_phone(value)

    @field_validator("password")
    @classmethod
    def check_password(cls, value):

        return validate_password(value)


class LoginRequest(BaseModel):

    email: EmailStr

    password: str = Field(
        min_length=1
    )


class VerificationRequest(BaseModel):

    aadhaar_number: str

    name: str = Field(
        min_length=2,
        max_length=100
    )

    date_of_birth: str

    @field_validator("aadhaar_number")
    @classmethod
    def check_aadhaar(cls, value):

        value = value.strip()

        if not re.fullmatch(
            r"[0-9]{12}",
            value
        ):

            raise ValueError(
                "Aadhaar number must contain exactly 12 digits"
            )

        return value

    @field_validator("name")
    @classmethod
    def check_verification_name(cls, value):

        return validate_name(value)

    @field_validator("date_of_birth")
    @classmethod
    def check_date_of_birth(cls, value):

        value = value.strip()

        if not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}",
            value
        ):

            raise ValueError(
                "Date of birth must use YYYY-MM-DD format"
            )

        return value


# =========================================================
# RESPONSE MODELS
# =========================================================

class UserResponse(BaseModel):

    id: int
    name: str
    email: str
    phone: str
    is_active: bool

    class Config:
        from_attributes = True


class VerificationResponse(BaseModel):

    id: int
    user_id: int
    masked_aadhaar: str
    name: str
    date_of_birth: str
    status: str
    message: str
    ai_score: int
    risk_level: str

    class Config:
        from_attributes = True


# =========================================================
# ROOT
# =========================================================

@app.get("/")
def root():

    return {
        "success": True,
        "message": "UIDAI Backend is running",
        "status": "success"
    }


# =========================================================
# REGISTER
# =========================================================

@app.post("/auth/register")
def register(
    user: UserCreate,
    db: Session = Depends(get_db)
):

    existing_user = db.query(User).filter(
        User.email == user.email
    ).first()

    if existing_user:

        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    existing_phone = db.query(User).filter(
        User.phone == user.phone
    ).first()

    if existing_phone:

        raise HTTPException(
            status_code=400,
            detail="Phone number already registered"
        )

    new_user = User(

        name=user.name,

        email=user.email,

        phone=user.phone,

        password=hash_password(
            user.password
        )
    )

    db.add(new_user)

    db.commit()

    db.refresh(new_user)

    return {

        "success": True,

        "message": "User registered successfully",

        "user_id": new_user.id
    }


# =========================================================
# LOGIN
# =========================================================

@app.post("/auth/login")
def login(
    login_data: LoginRequest,
    db: Session = Depends(get_db)
):

    user = db.query(User).filter(
        User.email == login_data.email
    ).first()

    if not user:

        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    if not verify_password(
        login_data.password,
        user.password
    ):

        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    if not user.is_active:

        raise HTTPException(
            status_code=403,
            detail="User account is inactive"
        )

    access_token = create_access_token(

        data={
            "sub": str(user.id),
            "email": user.email
        }
    )

    return {

        "success": True,

        "message": "Login successful",

        "access_token": access_token,

        "token_type": "bearer"
    }


# =========================================================
# CURRENT USER
# =========================================================

@app.get(
    "/auth/me",
    response_model=UserResponse
)
def get_my_profile(
    current_user: User = Depends(
        get_current_user
    )
):

    return current_user


# =========================================================
# CREATE VERIFICATION
# =========================================================

@app.post(
    "/verification/",
    response_model=VerificationResponse
)
def verify_identity(

    verification_data: VerificationRequest,

    current_user: User = Depends(
        get_current_user
    ),

    db: Session = Depends(get_db)
):

    result = perform_demo_verification(

        verification_data.aadhaar_number,

        verification_data.name,

        verification_data.date_of_birth
    )

    if result["status"] == "FAILED":

        raise HTTPException(
            status_code=400,
            detail=result["message"]
        )

    ai_result = analyze_verification(

        verification_data.aadhaar_number,

        verification_data.name,

        verification_data.date_of_birth
    )

    existing_verification = db.query(
        Verification
    ).filter(

        Verification.user_id
        == current_user.id,

        Verification.aadhaar_hash
        == result["aadhaar_hash"]

    ).first()

    if existing_verification:

        raise HTTPException(
            status_code=409,
            detail="This Aadhaar is already verified for this user"
        )

    verification = Verification(

        user_id=current_user.id,

        aadhaar_hash=result["aadhaar_hash"],

        masked_aadhaar=result["masked_aadhaar"],

        name=verification_data.name,

        date_of_birth=verification_data.date_of_birth,

        status=result["status"],

        message=result["message"],

        ai_score=ai_result["score"],

        risk_level=ai_result["risk_level"]
    )

    db.add(verification)

    db.commit()

    db.refresh(verification)

    return verification


# =========================================================
# VERIFICATION HISTORY
# =========================================================

@app.get(
    "/verification/",
    response_model=list[VerificationResponse]
)
def get_my_verifications(

    current_user: User = Depends(
        get_current_user
    ),

    db: Session = Depends(get_db)
):

    return db.query(
        Verification
    ).filter(

        Verification.user_id
        == current_user.id

    ).order_by(

        Verification.id.desc()

    ).all()


# =========================================================
# SINGLE VERIFICATION
# =========================================================

@app.get(
    "/verification/{verification_id}",
    response_model=VerificationResponse
)
def get_verification(

    verification_id: int,

    current_user: User = Depends(
        get_current_user
    ),

    db: Session = Depends(get_db)
):

    verification = db.query(
        Verification
    ).filter(

        Verification.id == verification_id,

        Verification.user_id == current_user.id

    ).first()

    if not verification:

        raise HTTPException(
            status_code=404,
            detail="Verification record not found"
        )

    return verification


# =========================================================
# GET ALL USERS
# =========================================================

@app.get(
    "/users/",
    response_model=list[UserResponse]
)
def get_users(
    db: Session = Depends(get_db)
):

    return db.query(
        User
    ).all()


# =========================================================
# GET USER
# =========================================================

@app.get(
    "/users/{user_id}",
    response_model=UserResponse
)
def get_user(

    user_id: int,

    db: Session = Depends(get_db)
):

    user = db.query(
        User
    ).filter(

        User.id == user_id

    ).first()

    if not user:

        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    return user


# =========================================================
# UPDATE USER
# =========================================================

@app.put(
    "/users/{user_id}",
    response_model=UserResponse
)
def update_user(

    user_id: int,

    user_data: UserCreate,

    db: Session = Depends(get_db)
):

    user = db.query(
        User
    ).filter(

        User.id == user_id

    ).first()

    if not user:

        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    user.name = user_data.name
    user.email = user_data.email
    user.phone = user_data.phone

    db.commit()

    db.refresh(user)

    return user


# =========================================================
# DELETE USER
# =========================================================

@app.delete(
    "/users/{user_id}"
)
def delete_user(

    user_id: int,

    db: Session = Depends(get_db)
):

    user = db.query(
        User
    ).filter(

        User.id == user_id

    ).first()

    if not user:

        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    db.delete(user)

    db.commit()

    return {

        "success": True,

        "message": "User deleted successfully"
    }