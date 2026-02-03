import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Flask configuration from environment variables"""
    
    # OpenAI Configuration
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    
    # MySQL Configuration
    MYSQL_HOST = os.getenv("MYSQL_HOST")
    MYSQL_PORT = int(os.getenv("MYSQL_PORT"))
    MYSQL_DB = os.getenv("MYSQL_DB")
    MYSQL_USER = os.getenv("MYSQL_USER")
    MYSQL_PASS = os.getenv("MYSQL_PASS")
    
    # Flask Configuration
    PORT = int(os.getenv("PORT", "5002"))
    DEBUG = os.getenv("FLASK_DEBUG", "0") == "1"
    JSON_SORT_KEYS = False

