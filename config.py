import os

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-key")
    SESSION_TYPE = "filesystem"
    SESSION_PERMANENT = False
