from sqlalchemy import create_engine, Column, Integer, String, DateTime, Enum, UniqueConstraint
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import enum
from datetime import datetime
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, String, Boolean

Base = declarative_base()



class Application(Base):
    __tablename__ = 'applications'
    __table_args__ = (UniqueConstraint('package_identifier', name='uix_package_identifier'),)

    app_id = Column(Integer, primary_key=True, autoincrement=True)
    app_name = Column(String(255), nullable=False)
    package_identifier = Column(String(255), nullable=False)
    current_version = Column(String(50))
    available_update = Column(String(50))
    last_checked = last_checked = Column(DateTime, default=datetime.utcnow)




class PatchHistory(Base):
    __tablename__ = "patch_history"

    history_id = Column(Integer, primary_key=True)
    app_id = Column(Integer, ForeignKey("applications.app_id"))
    patch_version = Column(String(50))
    installed_on = Column(DateTime, default=datetime.utcnow)
    status = Column(String(20))  # "success", "failed", etc.

    application = relationship("Application", back_populates="patch_history")



class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_admin = Column(Boolean, default=False)



Application.patch_history = relationship("PatchHistory", back_populates="application")

engine = create_engine('mysql+pymysql://root:Sterben1999!@localhost/Patch_Management')
Session = sessionmaker(bind=engine)
session = Session()

Base.metadata.create_all(engine)