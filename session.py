from typing import Generator, Type

# import database # noqaz
from sqlalchemy import Engine
from sqlalchemy.orm import Session
from sqlmodel import SQLModel, create_engine


class SingletonMeta(type):
    """
    The Singleton class can be implemented in different ways in Python. Some
    possible methods include: base class, decorator, metaclass. We will use the
    metaclass because it is best suited for this purpose.
    """

    _instances: dict[Type, "SingletonMeta"] = {}

    def __call__(cls, *args, **kwargs):
        """
        Possible changes to the value of the `__init__` argument do not affect
        the returned instance.
        """
        if cls not in cls._instances:
            instance = super().__call__(*args, **kwargs)
            cls._instances[cls] = instance
        return cls._instances[cls]


class DatabaseSessionManager(metaclass=SingletonMeta):
    _instance = None
    _engine: Engine = None

    @staticmethod
    def get_instance():
        """Static access method."""
        if DatabaseSessionManager._instance is None:
            DatabaseSessionManager()
        return DatabaseSessionManager._instance

    def __init__(self):
        """Virtually private constructor."""
        if DatabaseSessionManager._instance is not None:
            raise Exception("This class is a singleton!")
            print("This class in a Singleton!")
        else:
            DatabaseSessionManager._instance = self
            DATABASE_URL = "sqlite:///./mitm.db"
            DatabaseSessionManager._engine = create_engine(DATABASE_URL, echo=True)
            SQLModel.metadata.create_all(DatabaseSessionManager._engine)

    def get_session_fastapi(self) -> Generator:
        with Session(DatabaseSessionManager._engine) as session:
            yield session

    def get_session(self) -> Session:
        return Session(DatabaseSessionManager._engine)


if __name__ == "__main__":
    s1 = DatabaseSessionManager()

    s2 = DatabaseSessionManager()
    if id(s1) == id(s2):
        print("Same")
    else:
        print("Different")
