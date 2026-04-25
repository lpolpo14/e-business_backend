"""
In this file methods are provided for loading the JSON MITRE D3FEND Data into
the SQLite Data Base. This allows for reproducable results for each machine.
"""

import json, sqlite3
from d3fender.database.db import Database
from d3fender.models.defendModels import DefendTactic, DefendTechnique

def dataIngest():
    """
    This function is responsible for the whole installation of the D3FEND JSON knowledge base to the SQLite Database
    """
    parseFile(retrieveD3FENDJson())

def retrieveD3FENDJson(pathD3FEND = "d3fend.json"):
    """
        Retrieves the whole JSON Dictionary from the d3fend json file.
        Args:
            pathD3FEND: The path for the D3FEND JSON File.
        Returns:
            The whole dictionary containing the JSON dictionary from the D3FEND json file.
    """
    d3fend_data = "Future JSON"
    with open(pathD3FEND) as json_file:
        d3fend_data = json.load(json_file)

    return d3fend_data["@graph"] # Contains all the d3fend JSON-LD Graph data.

def isDefensiveTechnique(obj):
    """
    Checks if a given JSON object is a Defensive Technique
    Args:
        obj: A JSON Object.
    """
    

def parseFileWithoutRelations(d3fend_data, pathDB= None):
    """
    The secondary parser for the D3FEND JSON File. This method does not parse
    the relationships between the database's objects. This means we do not know
    the subclasses and upper classes - therefore cannot deduce the tactic of a specific technique.
    The retrieved Tactics and Techniques are saved to the main SQLite database.
    Args:
            d3fend_data: The JSON Dictionary which contains the D3FEND Framework's data 
            pathDB: The path to the main Database
    """
    
    db = Database(pathDB)

    for obj in d3fend_data:
        if "d3f:DefensiveTactic" in obj.get("@type", ""):
            tactic = DefendTactic(obj["@id"],
                                  obj["rdfs:label"],
                                  obj["d3f:definition"])
            tactic.addToDB(db)
        elif obj.get("d3f:d3fend-id", "").startswith("D3-"): # See Docs/D3FEND_doc.md
            technique = DefendTechnique(obj["@id"],
                                        obj["d3f:d3fend-id"],
                                        obj["rdfs:label"],
                                        obj.get("d3f:definition",""),
                                        obj.get("d3f:kb-article",""))
            technique.addToDB(db)
    db.commit()
    db.close()

def parseFileDeprecated(d3fend_data, pathDB="mitre.db"):
    """
    The main parser for the D3FEND JSON File. This method parses and retrieves
    all the Techniques and Tactics of the D3FEND Knowledge base, including
    the relations between them.
    The retrieved Tactics and Techniques are saved to the main SQLite database.

    This Version is deprecated.
    Args:
        d3fend_data: The JSON Dictionary which contains the D3FEND Framework's data
        pathDB: The path to the main Database
    """
    db = Database(pathDB)

    for obj in d3fend_data:
        if "d3f:DefensiveTactic" in obj.get("@type", ""):
            tactic = DefendTactic(obj["@id"],
                                  obj["rdfs:label"],
                                  obj["d3f:definition"])
            tactic.addToDB(db)
        elif obj.get("d3f:d3fend-id", "").startswith("D3-"):  # See Docs/D3FEND_doc.md
            technique = DefendTechnique(obj["@id"],
                                        obj["d3f:d3fend-id"],
                                        obj["rdfs:label"],
                                        obj.get("d3f:definition", ""),
                                        obj.get("d3f:kb-article", ""),
                                        getSubClassOf(obj))
            technique.addToDB(db)
    db.commit()
    db.close()

def parseFile(d3fend_data, pathDB=None):
    """
    The main parser for the D3FEND JSON File. This method parses and retrieves
    all the Techniques and Tactics of the D3FEND Knowledge base, including
    the relations between them.
    The retrieved Tactics and Techniques are saved to the main SQLite database.

    This method saves the complete objects to the Tables Tactics and Techniques.
    That means all Relations are properly calculated, as well as the tactic of each Technique.
    Args:
        d3fend_data: The JSON Dictionary which contains the D3FEND Framework's data
        pathDB: The path to the main Database
    """
    Tactics = []
    Techniques = []
    TechniqueIndex = {}
    for obj in d3fend_data:
        if "d3f:DefensiveTactic" in obj.get("@type", ""):
            tactic = DefendTactic(obj["@id"],
                                  obj["rdfs:label"],
                                  obj["d3f:definition"])
            TechniqueIndex[obj["@id"]] = tactic
            Tactics.append(tactic)
        elif obj.get("d3f:d3fend-id", "").startswith("D3-"):  # See Docs/D3FEND_doc.md
            technique = DefendTechnique(obj["@id"],
                                        obj["d3f:d3fend-id"],
                                        obj["rdfs:label"],
                                        obj.get("d3f:definition", ""),
                                        obj.get("d3f:kb-article", ""),
                                        getSubClassOf(obj))
            TechniqueIndex[obj["@id"]] = technique
            Techniques.append(technique)
    db = Database(pathDB)
    for tactic in Tactics:
        tactic.addToDB(db)
    for technique in Techniques:
        technique.calculateTactic(TechniqueIndex)
        technique.addToDB(db)
    db.commit()
    db.close()

def getSubClassOf(obj) -> str or None:
    """
    Retrieves the main SubClassOf Field from the D3FEND JSON file for a specific Technique.
    Args:
        obj: A JSON Object representing a technique from the D3FEND JSON file
    Returns:
        A string containing the identifier for the superclass of the Technique, or None if not found.
    """
    entries = ensureList(obj.get("rdfs:subClassOf"))
    for entry in entries:
        # If Entry is a dict
        if isinstance(entry, dict):
            subclass_id = entry.get("@id")
        elif isinstance(entry, str): #If entry is a string
            subclass_id = entry
        else:
            continue

        # In this case we have a Main Technique of a Tactic
        if subclass_id == "d3f:DefensiveTechnique":
            subclass_id = obj.get("d3f:enables","").get("@id", "")

        if subclass_id and subclass_id.startswith("d3f:"):
            return subclass_id
    return None

def ensureList(value):
    """
    Simple function that ensures that the parameter is a list.
    """
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return value
    return []
