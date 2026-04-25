"""
This is a singleton class which implements important database functionality.
When another object wants to use the database, it always uses this object.
This allows for more effective and safe DB Usage.
"""

import sqlite3
from pathlib import Path

class Database:
    """
    This is a singleton class which implements important database functionality.
    When another object wants to use the database, it always uses this object.
    This allows for more effective and safe DB Usage.
    """
    def __init__(self, path = None):
        """
        The initializator for the database. It also initializes the cursor, though
        seldom used by other objects when interacting.
        Args:
            path: The path to the database file (.db). The existence of this parameter
            allows for easier incorperation of testing.
        """
        if path is None:
            base_dir = Path(__file__).resolve().parent.parent
            db_path = base_dir / "resources" / "mitre.db"
        else:
            db_path = Path(path)
        self.path = db_path
        self.conn = sqlite3.connect(self.path)
        self.cursor = self.conn.cursor()

    def execute(self, query, params=None):
        """
        A method which executes a specific query with the given parameters.
        Args:
            query: A SQL Query (SQLite Syntax)
            params: Params used for the query (Parametrized Queries)
        Returns: A cursor
        """
        params = params or ()
        self.cursor.execute(query, params)
        return self.cursor

    def commit(self):
        """
        Wrapper function for a database commit operation.
        """
        self.conn.commit()

    def close(self):
        """
        Wrapper function for a database close operation.
        """
        self.conn.close()
