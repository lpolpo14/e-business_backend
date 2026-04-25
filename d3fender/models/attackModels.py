"""
This file contains the models used in the ATT&CK Framework. The functions contain important logic that interacts with the database. 
"""
from d3fender.database.db import Database

class AttackTactic:
    """
    This class acts as a model for the tactics present in the ATT&CK MITRE Knowledge Base.
    """
    def __init__(self, id, name, shortname, description):
        """
        Initializer. Fields represent how the object is saved in the data base.
        Args:
            id: Tactic Identifier
            name: Tactic Name
            shortname: Short name of the tactic used for mapping Technique -> Tactic
            description: Description of the Tactic
        """
        self.id = id 
        self.name = name
        self.shortname = shortname
        self.description = description

    def addToDB(self, db):
        """
        Method which adds a given AttackTactic object to the database.
        Args:
            db: A Database Object. The AttackTactic object is saved here.
        """
        insert_query = "INSERT INTO ATTACK_TACTICS (id, name, shortname, description) VALUES (?, ?, ?, ?)"
        db.execute(insert_query, (self.id, self.name, self.shortname, self.description))

class AttackTechnique:
    """
    This class acts as a model for the techniques and subtechniques present in the ATT&CK MITRE Knowledge Base
    """
    def __init__(self, id, external_id, name, description, tactics):
        """
        Initializer. Fields represent how the object is saved in the database.
        Args:
            id: Technique Identifier based solely on the JSON file
            external_id: External ID matches the ID provided and shown on the MITRE website. It is saved 
            so any future mappings can be easier.
            name: Technique name
            description: Description of the technique
            tactics: A JSON String which map the specific technique to the tactics it belongs.
        """
        self.id = id 
        self.external_id = external_id
        self.name = name
        self.description = description
        self.tactics = tactics


    def addToDB(self, db):
        """
        Method which adds a given AttackTechnique object to the data base.
        Args:
            db: A Database Object. The AttackTactic object is saved here.
        """
        insert_query = "INSERT INTO ATTACK_TECHNIQUES (id, external_id, name, description, tactics) VALUES (?, ?, ?, ?, ?)"
        db.execute(insert_query, (self.id, self.external_id, self.name, self.description, self.tactics))
