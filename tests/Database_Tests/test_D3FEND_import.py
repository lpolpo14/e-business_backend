"""
This file contains tests regarding the importation of the Mitre D3FEND Knowledge Base.
The input is automated and the files are downloaded on the computer that the app is running on.
"""

import pytest
import json
import tomllib
import pathlib
from d3fender.database.db_schema import initializeDB
from d3fender.database.db import Database
from d3fender.data_loaders.import_d3fend import parseFile, retrieveD3FENDJson, parseFileWithoutRelations, \
    parseFileDeprecated


def testParseInput_RealDataWithoutRelations(pytestconfig,tmp_path):
    """
    This function tests every side of the Parse Method used during the D3FEND JSON file parsing.
    It uses Real Data. Might change in the future.
    Args:
        pytestconfig:   configuration for pytest used to get the
        root path so we can replicate tests.
        tmp_path:   tmp_path is a global pytest variable that gives us a temporary
        path for us to conduct our testing.
    """

    db_path = tmp_path / "test.db"


    project_root = pathlib.Path(pytestconfig.rootpath)
    mockDataPath = project_root / "d3fender/data_loaders/d3fend.json"

    initializeDB(db_path)

    parseFileWithoutRelations(retrieveD3FENDJson(mockDataPath), db_path)
    temp_db = Database(db_path)
    row = temp_db.execute("SELECT COUNT(*) FROM DEFEND_TACTICS").fetchone()
    assert row[0] == 7
   
    row = temp_db.execute("SELECT COUNT(*) FROM DEFEND_TECHNIQUES").fetchone()
    assert row[0] == 249 # There are indeed 249 Techniques, which is strange since on the site only 248 are visible..

def testParseInput_RealDataWithRelations_NoTactics(pytestconfig,tmp_path):
    """
        This function uses the deprecated function to calculate all the Techniques and Tactics
        of the D3FEND JSON file. No Tactics are saved. While deprecated, it is still useful.
        Args:
            pytestconfig:   configuration for pytest used to get the
            root path so we can replicate tests.
            tmp_path:   tmp_path is a global pytest variable that gives us a temporary
            path for us to conduct our testing.
        """

    db_path = tmp_path / "test.db"

    project_root = pathlib.Path(pytestconfig.rootpath)
    mockDataPath = project_root / "d3fender/data_loaders/d3fend.json"

    initializeDB(db_path)

    parseFileDeprecated(retrieveD3FENDJson(mockDataPath), db_path)
    temp_db = Database(db_path)
    row = temp_db.execute("SELECT COUNT(*) FROM DEFEND_TACTICS").fetchone()
    assert row[0] == 7

    row = temp_db.execute("SELECT COUNT(*) FROM DEFEND_TECHNIQUES").fetchone()
    assert row[0] == 249  # There are indeed 249 Techniques, which is strange since on the site only 248 are visible..

def testParseInput_RealDataWithRelationsAndTactics(pytestconfig,tmp_path):
    """
        This function calculates and retrieves all the Tactics and Techniques from the
        D3FEND JSON File. All fields are calculated.
        Args:
            pytestconfig:   configuration for pytest used to get the
            root path so we can replicate tests.
            tmp_path:   tmp_path is a global pytest variable that gives us a temporary
            path for us to conduct our testing.
        """

    db_path = tmp_path / "test.db"

    project_root = pathlib.Path(pytestconfig.rootpath)
    mockDataPath = project_root / "d3fender/data_loaders/d3fend.json"

    initializeDB(db_path)

    parseFile(retrieveD3FENDJson(mockDataPath), db_path)
    temp_db = Database(db_path)
    row = temp_db.execute("SELECT COUNT(*) FROM DEFEND_TACTICS").fetchone()
    assert row[0] == 7

    row = temp_db.execute("SELECT COUNT(*) FROM DEFEND_TECHNIQUES").fetchone()
    assert row[0] == 249  # Strangely, the JSON file contains an error : A Time Analysis Technique called ARMA
    # from the Analytic Technique Taxonomy has a flawed ID. Instead of D3A-... it got assigned D3-...
    # Still, this is not an error.


    row = temp_db.execute("SELECT COUNT(*) FROM DEFEND_TECHNIQUES WHERE tactic = 'Unknown'").fetchone()
    assert row[0] == 1 # Due to the ARMA Inclusion

    row = temp_db.execute("SELECT COUNT(*) FROM DEFEND_TECHNIQUES WHERE tactic == 'd3f:Deceive'").fetchone()
    assert row[0] == 11


