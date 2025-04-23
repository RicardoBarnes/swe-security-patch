from fastapi import FastAPI
from api import app as api_router 
from models import Base, engine
import crud
from new_database_population import detect_and_sync 

app = FastAPI()


app.include_router(api_router, prefix="")  

Base.metadata.create_all(engine)

detect_and_sync()