from app.database import engine, Base
from app.models import User, Role, Key, AuditLog

def init():
    print("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    print("Done.")

if __name__ == "__main__":
    init()