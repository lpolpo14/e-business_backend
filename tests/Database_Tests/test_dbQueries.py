"""
In this module tests are performed to measure the effectiveness
of the queries executed with the db_queries.py module.
"""

import pytest
import pathlib

from d3fender.data_loaders.import_attack import retrieveATTACKJson
from d3fender.database.db_schema import initializeDB
from d3fender.database.db import Database
from d3fender.data_loaders.import_d3fend import parseFile, retrieveD3FENDJson
from d3fender.database.db_queries import getD3FENDTechnique, getD3FENDTactic, getATTACKTechnique, getATTACKTactic
from d3fender.models.attackModels import AttackTechnique, AttackTactic
from d3fender.models.defendModels import DefendTechnique, DefendTactic


def test_getD3FENDTechnique(pytestconfig,tmp_path):
    """
    Method tests specifically the getD3FENDTechnique method
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

    technique = getD3FENDTechnique("D3-SSC",db_path)
    assert isinstance(technique, DefendTechnique)
    assert technique.defend_id == "D3-SSC"

def test_getD3FENDTactic(pytestconfig,tmp_path):
    """
        Method tests specifically the getD3FENDTactic method
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

    tactic = getD3FENDTactic("d3f:Model", db_path)
    assert isinstance(tactic, DefendTactic)
    assert tactic.name == "Model"

"""
# Fix data contamination later
def test_getATTACKTechniques(pytestconfig,tmp_path):
           # Method tests specifically the getATTACKTechnique method
           # Args:
           #         pytestconfig:   configuration for pytest used to get the
           #         root path so we can replicate tests.
           #         tmp_path:   tmp_path is a global pytest variable that gives us a temporary
           #         path for us to conduct our testing.  

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

    #technique = getATTACKTechnique("T1669", db_path)
    #assert isinstance(technique, AttackTechnique)
    #assert technique.id == "T1071.001"

# Fix data contamination later
def test_getATTACKTactics(pytestconfig,tmp_path):
        #        Method tests specifically the getATTACKTactic method
        #        Args:
        #                pytestconfig:   configuration for pytest used to get the
        #                root path so we can replicate tests.
        #                tmp_path:   tmp_path is a global pytest variable that gives us a temporary
        #                path for us to conduct our testing.
    db_path = tmp_path / "test.db"

    project_root = pathlib.Path(pytestconfig.rootpath)
    mockDataPath = project_root / "d3fender/data_loaders/enterprise-attack.json"

    initializeDB(db_path)

    parseFile(retrieveATTACKJson(mockDataPath), db_path)

    tactic = getATTACKTactic("TA0004", db_path)
    assert isinstance(tactic, AttackTactic)
    assert tactic.id == "TA0004"
"""