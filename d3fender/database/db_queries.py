"""
This module contains useful queries that may be used by other packages
in order to retrieve specific information from the database.
"""
from d3fender.database.db import Database
from d3fender.models.attackModels import AttackTechnique, AttackTactic
from d3fender.models.defendModels import DefendTechnique, DefendTactic


def getD3FENDTechnique(id : str, dbPath: str = None) -> DefendTechnique or None:
    """
    Retrieves a D3FEND Technique from the database using the D3FEND ID.
    Args:
        id: The id of the Technique based on the site.
        dbPath: The path to the database.
    Returns: A DefendTechnique object if found, otherwise None.
    """
    db = Database(dbPath)
    query = """ SELECT id, defend_id, name, definition,
    description, subClassOf, tactic 
    FROM DEFEND_TECHNIQUES
    WHERE defend_id = ?
    """
    cursor = db.execute(query, (id,))
    cursor = cursor.fetchone()
    db.close()
    if cursor is None:
        return None
    return DefendTechnique(cursor[0], cursor[1], cursor[2], cursor[3], cursor[4], cursor[5], cursor[6])

def getD3FENDTactic(id : str, dbPath: str = None) -> DefendTactic or None:
    """
    Retrieves a D3FEND Tactic from the database using the D3FEND ID.
    Args:
        id: The id of the Tactic based on the site.
        dbPath: The path to the database.
    Returns: A DefendTactic object if found, otherwise None.
    """
    db = Database(dbPath)
    query = """ SELECT id, name, definition
        FROM DEFEND_TACTICS
        WHERE id = ?
        """
    cursor = db.execute(query, (id,))
    cursor = cursor.fetchone()
    db.close()
    if cursor is None:
        return None
    return DefendTactic(cursor[0], cursor[1], cursor[2])

def getATTACKTechnique(id : str, dbPath: str = None) -> AttackTechnique or None:
    """
    Retrieves an ATT&CK Technique from the database using the D3FEND ID.
    Args:
        id: The id of the Technique based on the site.
        dbPath: The path to the database.
    Returns: A AttackTechnique object if found, otherwise None.
    """
    db = Database(dbPath)
    query = """ SELECT id, external_id, name, description, tactics
        FROM ATTACK_TECHNIQUES
        WHERE external_id = ?
        """
    cursor = db.execute(query, (id,))
    cursor = cursor.fetchone()
    db.close()
    if cursor is None:
        return None
    return AttackTechnique(cursor[0], cursor[1], cursor[2], cursor[3], cursor[4])


def getATTACKTactic(id : str, dbPath: str = None) -> AttackTactic or None:
    """
    Retrieves an ATT&CK Tactic from the database using the D3FEND ID.
    Args:
        id: The id of the Tactic based on the site.
        dbPath: The path to the database.
    Returns: A AttackTactic object if found, otherwise None.
    """
    db = Database(dbPath)
    query = """ SELECT id, name,shortname, description
            FROM ATTACK_TACTICS
            WHERE id = ?
            """
    cursor = db.execute(query, (id,))
    cursor = cursor.fetchone()
    db.close()
    if cursor is None:
        return None
    return AttackTactic(cursor[0], cursor[1], cursor[2], cursor[3])