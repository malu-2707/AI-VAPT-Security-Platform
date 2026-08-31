from app.database import engine
from app.models.user import Base, User
from app.models.target import Target
from app.models.scan import Scan
from app.models.finding import Finding

print("Creating database tables...")

Base.metadata.create_all(engine)

print("Database tables created successfully!")

