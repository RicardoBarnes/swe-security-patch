from models import User, Session
from auth import hash_password

# Start DB session
db = Session()

# Create admin user
admin = User(
    username="admin",
    hashed_password=hash_password("admin123"),  # Change password if needed
    is_admin=True
)

# Add to DB
db.add(admin)
db.commit()
db.close()

print("✅ Admin user created.")
