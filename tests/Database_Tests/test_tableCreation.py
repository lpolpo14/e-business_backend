"""
Here we check if all the necessary tables for the database are created and ready for use.
We do not test Insertion or Updates.
"""

import pytest
import d3fender.database.db_schema as CT
import d3fender.database.db as DB

@pytest.fixture
def testAttackTablesCreation(tmp_path):
    """
    Tests whether all the tables in the db are created properly to accomodate
    for the ATT&CK Framework.
    """

    CT.createTableTechniques(tmp_path / "test.db")
    CT.createTableTactics(tmp_path / "test.db")

    test_db = DB.Database(tmp_path / "test.db")

    cur = test_db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='Techniques';")
    row = cur.fetchone()
    assert row is not None


    cur = test_db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='Tactics';")
    row = cur.fetchone()
    assert row is not None

