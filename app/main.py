from fastapi import FastAPI
from app.routes import user, auth

app = FastAPI(
    title="UIDAI Backend",
    description="Backend API for UIDAI-inspired project",
    version="1.0.0"
)

app.include_router(user.router)
app.include_router(auth.router)

@app.get("/")
def home():
    return {
        "message": "UIDAI Backend is running!"
    }    