"""
This file contains tests regarding the importation of the Mitre ATT&CK Knowledge Base.
The input is automated and the files are downloaded on the computer that the app is running on.
"""

import pytest
from d3fender.data_loaders.import_attack import parseFile, retrieveATTACKJson
from d3fender.database.db_schema import initializeDB
from d3fender.database.db import Database
import json
import tomllib
import pathlib

def testParseInput(pytestconfig,tmp_path):
    """
    This function tests every side of the Parse Method used during the ATT&CK JSON file parsing.
    It uses Mock Data.
    Args:
        pytestconfig:   configuration for pytest used to get the
        root path so we can replicate tests.
        tmp_path:   tmp_path is a global pytest variable that gives us a temporary
        path for us to conduct our testing.
    """
    db_path = tmp_path / "test.db"


    project_root = pathlib.Path(pytestconfig.rootpath)
    mockDataPath = project_root / "tests/mockData/attackMock.json"

    initializeDB(db_path)

    parseFile(retrieveATTACKJson(mockDataPath), db_path)
    temp_db = Database(db_path)
    row = temp_db.execute("SELECT COUNT(*) FROM ATTACK_TACTICS").fetchone()
    assert row[0] == 2
   
    row = temp_db.execute("SELECT COUNT(*) FROM ATTACK_TECHNIQUES").fetchone()
    assert row[0] == 2
    temp_db.close()
    # Add a test case where external_reference is lacking for the techniques!

def testParseInput_RealData(pytestconfig,tmp_path):
    """
    This function tests every side of the Parse Method used during the ATT&CK JSON file parsing.
    It uses Real Data. Might change in the future.
    Args:
        pytestconfig:   configuration for pytest used to get the
        root path so we can replicate tests.
        tmp_path:   tmp_path is a global pytest variable that gives us a temporary
        path for us to conduct our testing.
    """

    db_path = tmp_path / "test.db"


    project_root = pathlib.Path(pytestconfig.rootpath)
    mockDataPath = project_root / "d3fender/data_loaders/enterprise-attack.json"

    initializeDB(db_path)

    parseFile(retrieveATTACKJson(mockDataPath), db_path)
    temp_db = Database(db_path)
    row = temp_db.execute("SELECT COUNT(*) FROM ATTACK_TACTICS").fetchone()
    assert row[0] == 14
   
    row = temp_db.execute("SELECT COUNT(*) FROM ATTACK_TECHNIQUES").fetchone()
    assert row[0] == 691
    # Add a test case where external_reference is lacking for the techniques!
    temp_db.close()

