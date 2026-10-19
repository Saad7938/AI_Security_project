"""Run the gateway:  python -m gateway.serve   (reads .env.gateway if present)."""
import os

import uvicorn
from dotenv import load_dotenv

from .config import Config
from .service import create_app

if __name__ == "__main__":
    load_dotenv(".env.gateway")
    uvicorn.run(create_app(Config.from_env()), host="127.0.0.1",
                port=int(os.environ.get("GATEWAY_PORT", "8000")), log_level="warning")
