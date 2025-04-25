from models import User, Session
from auth import hash_password


db = Session()


admin = User(
    username="admin",
    hashed_password=hash_password("admin123"),
    is_admin=True
)


db.add(admin)
db.commit()
db.close()

print("Admin user created.")
