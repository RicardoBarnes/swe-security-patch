from fastapi import FastAPI
from api import router as api_router
from models import Base, engine

app = FastAPI()
app.include_router(api_router)
Base.metadata.create_all(engine)
