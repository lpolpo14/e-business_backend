"""
In this python code we call all the proper functions from the various other files
so we can download all the MITRE data (both ATT&CK and D3FEND) and store them
in our database.
"""

import import_attack
import import_d3fend
from d3fender.database.db_schema import initializeDB

initializeDB()
import_attack.dataIngest()
import_d3fend.dataIngest()
