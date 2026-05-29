import sys
from database import engine
import models

def create_tables(reset=False):
    if reset:
        print("Resetting database...")
        models.Base.metadata.drop_all(bind=engine)
        print("All tables dropped.")
    
    print("Creating database tables...")
    models.Base.metadata.create_all(bind=engine)
    print("Database tables created successfully.")

if __name__ == "__main__":
    reset = len(sys.argv) > 1 and sys.argv[1] == "--reset"
    create_tables(reset)
