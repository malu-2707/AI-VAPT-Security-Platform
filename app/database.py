from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "postgresql+psycopg://q:123@127.0.0.1:5432/vapt_db"

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False
)


def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


def test_database_connection():
    try:
        with engine.connect() as connection:
            result = connection.execute(
                text("SELECT current_user, current_database();")
            )

            user, database = result.fetchone()

            print("Database connection successful!")
            print("PostgreSQL user:", user)
            print("Connected database:", database)

            return True

    except Exception as error:
        print("Database connection failed!")
        print(error)

        return False

