"""SQLAlchemy foundation: the declarative Base and the DB initialization.

The engine is the entry point to the SQLite file and manages connections.
The Base collects every model's table metadata so create_all() can build them.
A Session is a single unit of work (one transaction) against the DB.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


class Base(DeclarativeBase):
    """All ORM models inherit from this so their tables register here."""
    pass


def init_db(db_path: str):
    """Builds the engine, creates any missing tables, returns a Session factory.

    Models must be imported before this runs so they are registered on
    Base.metadata – otherwise create_all() sees no tables to build.
    """
    engine = create_engine(f"sqlite:///{db_path}", echo=False)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)
