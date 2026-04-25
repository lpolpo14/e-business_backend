"""
This file contains all the models used in the D3FEND Framework. The functions contain logic that interacts with the database.
"""

from d3fender.database.db import Database

class DefendTactic:
    """
    This class represents a Tactic from the D3FEND Knowledge Base.
    """
    def __init__(self, id, name, definition):
        """
        Initializer. Parameters represent how the object will be saved in the DB.
        Args:
            id = the object's id based on the json file (Not the D3FEND Site)
            name = The name of the Tactic
            definition = the definition of the Tactic
        """
        self.id = id 
        self.name = name
        self.definition = definition

    def addToDB(self, db):
        """
        Method which adds a DefendTactic object to the given database
        Args:
            db: A Database Object where the DefendTactic will be saved.
        """
        insert_query = "INSERT INTO DEFEND_TACTICS (id, name, definition) VALUES (?, ?, ?)"
        db.execute(insert_query, (self.id, self.name, self.definition))

class DefendTechnique:
    """
    This class represents a Technique from the D3FEND Knowledge Base.
    """

    def __init__(self, id, defend_id, name, definition, description, subClassOf = None, tactic = None):
        """
        Initializer. Parameters represent how the object will be saved in the DB.
        Args:
            id: the object's id based on the json file (not the D3FEND Site)
            defend_id: the object's id based on how it is presented on the main D3FEND website.
            name: the name of the Technique
            definition: the definition of the technique (Nullable)
            description: the description of the technique (Nullable)
            subClassOf: The ID of the upper class of the current Technique
            tactic: The id of the Tactic the technique is a subclass of
        """
        self.id = id
        self.defend_id = defend_id
        self.name = name
        self.definition = definition
        self.description = description
        self.subClassOf = subClassOf
        self.tactic = tactic

    def addToDB(self, db):
        """
        Method which adds a DefendTechnique object to the given database
        Args:
            db: A Database Object where the DefendTactic will be saved.
        """
        insert_query = ("INSERT INTO DEFEND_TECHNIQUES (id, defend_id, name, definition,"
                        " description, subClassOf, tactic) VALUES (?, ?, ?, ?, ?, ?, ?)")
        db.execute(insert_query, (self.id, self.defend_id, self.name, self.definition, self.description, self.subClassOf, self.tactic))



    def calculateTactic(self, index: dict[str, object]) -> str:
        """
        Method which calculates the Tactic of the technique using an index of Techniques & Tactics.
        Args:
            index: An index type of object where key is the ID of a technique or Tactic,
            and the value is a DefendTechnique or DefendTactic Object
        """
        currentId = self.subClassOf
        while currentId:
            parent = index.get(currentId)
            if not parent:
                break

            if isinstance(parent, DefendTactic):
                self.tactic = parent.id
                return self.tactic
            currentId = getattr(parent, "subClassOf", None)

        self.tactic = "Unknown"
        return "Unknown"