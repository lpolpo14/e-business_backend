"""
In this file methods are provided for loading the JSON MITRE ATT&CK Data into
the SQLite Data Base. This allows for reproducable results for each machine.
"""

import json, sqlite3
from d3fender.database.db import Database
from d3fender.models.attackModels import AttackTactic, AttackTechnique

def dataIngest():
    """
    Method is responsible for creating the database and importing all the data from the
    ATT&CK Framework
    """

    parseFile(retrieveATTACKJson())

def retrieveATTACKJson(pathAttack="enterprise-attack.json"):
    """
        Retrieves the whole JSON Dictionary from the enterprise-attack json file.
        Args:
            pathAttack: The path for the ATT&CK Json File.
        Returns:
            The whole dictionary containing the JSON dictionary from the attack json file.
    """
    attack_data = "Future JSON"
    with open(pathAttack) as json_file:
        attack_data = json.load(json_file)

    return attack_data["objects"]

def getExternalID(obj):
    """
    Returns the external ID of an Attack Technique if present.
    Args:
        obj: a JSON object of type: "attack-pattern" from the ATT&CK JSON file.
    Returns:
        External ID of an Attack Technique
    """
    for ref in obj.get("external_references", []):
        if ref["source_name"] == "mitre-attack" and "external_id" in ref:
            return ref["external_id"]

def getTactics(obj):
    """
    Returns the Tactics associated with a specific technique
    Args:
        obj: a JSON object of type: "attack-pattern" from the ATT&CK JSON file.
    Returns:
        A String with the associated Tactics seperated with a space (' ').
    """
    tactics = []
    for phase in obj.get("kill_chain_phases",[]):
        if phase["kill_chain_name"] == "mitre-attack" and "phase_name" in phase:
            tactics.append(phase["phase_name"])
    return ' '.join(tactics)


def parseFile(attack_data,pathDB= None):
    """
        Responsible for parsing the json data and adding the Attack Tactics, Techniques
        and Relations to the database.
        Args:
            attack_data: The JSON Dictionary which contains the ATT&CK Framework's data 
            pathDB: The path to the main Database

    """
    db = Database(pathDB)

    for obj in attack_data:
        obj_type = obj.get("type","")
        if obj_type == "x-mitre-tactic":
            tactic = AttackTactic(obj["id"],
                                  obj["name"],
                                  obj["x_mitre_shortname"],
                                  obj["description"])
            tactic.addToDB(db)
        elif obj_type == "attack-pattern" and not obj.get("revoked",False) and not obj.get("x_mitre_deprecated", False):
            technique = AttackTechnique(obj.get("id",""), 
                                        getExternalID(obj),
                                        obj.get("name",""),
                                        obj.get("description",""),
                                        getTactics(obj))
            technique.addToDB(db)
    db.commit()
    db.close()

