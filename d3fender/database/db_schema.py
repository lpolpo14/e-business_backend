"""
This file contains methods that create all the tables in the DataBase.
"""
from d3fender.database.db import Database

def createTableAttackTechniques(db_path = None):
    db = Database(db_path)
    db.execute("DROP TABLE IF EXISTS ATTACK_TECHNIQUES")

    table_creation_query = """CREATE TABLE ATTACK_TECHNIQUES (
        id varchar(255) NOT NULL,
        external_id varchar(255) NOT NULL,
        name varchar(255) NOT NULL,
        description text,
        tactics text
    )
    """
    db.execute(table_creation_query)
    db.commit()
    db.close()

def createTableAttackTactics(db_path = None):
    db = Database(db_path)
    db.execute("DROP TABLE IF EXISTS ATTACK_TACTICS")

    table_creation_query = """CREATE TABLE ATTACK_TACTICS (
        id varchar(255) NOT NULL,
        name varchar(255) NOT NULL,
        shortname varchar(255) NOT NULL,
        description text NOT NULL
    )
    """
    db.execute(table_creation_query)
    db.commit()
    db.close()


def createTableDefendTechniques(db_path = None):
    db = Database(db_path)
    db.execute("DROP TABLE IF EXISTS DEFEND_TECHNIQUES")

    table_creation_query = """CREATE TABLE DEFEND_TECHNIQUES (
        id varchar(255) NOT NULL,
        defend_id varchar(255) NOT NULL,
        name varchar(255) NOT NULL,
        definition text,
        description text,
        subClassOf text,
        tactic text
    )
    """
    db.execute(table_creation_query)
    db.commit()
    db.close()


def createTableDefendTactics(db_path = None):
    db = Database(db_path)
    db.execute("DROP TABLE IF EXISTS DEFEND_TACTICS")

    table_creation_query = """CREATE TABLE DEFEND_TACTICS (
        id varchar(255) NOT NULL,
        name varchar(255) NOT NULL,
        definition text NOT NULL
    )
    """
    db.execute(table_creation_query)
    db.commit()
    db.close()



def initializeDB(db_path = None):
    """
    This method initializes all the tables in the database.
    """
    createTableAttackTactics(db_path)
    createTableAttackTechniques(db_path)
    createTableDefendTechniques(db_path)
    createTableDefendTactics(db_path)

