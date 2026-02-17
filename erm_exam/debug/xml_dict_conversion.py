"""

Test script to load an XML and then return an ordered dictionary of the mapping of column name to data-type for an Elden Ring
XML parameter definition file.

There are multiple ways to store the parameters definitions. The XML files are how Smithbox stores the parameter definitions. It was
well organized so I just took theirs to use and test with.
"""

import pprint
import xml.etree.ElementTree as ET
from pathlib import Path

from sty import (  # Terminal coloring library: foreground, background, effects, resetting
    bg, ef, fg, rs)


def main():
    repo_root = Path(__file__).absolute().parent.parent.parent
    
    # Try loading an xml from elden ring param defs
    # xml_path = repo_root / "data/elden_ring_param_definitions/BehaviorParam.xml"
    # xml_path = repo_root / "data/elden_ring_param_definitions/MoveParam.xml"
    xml_path = repo_root / "data/elden_ring_param_definitions/BulletParam.xml"
    # xml_path = repo_root / "data/elden_ring_param_definitions/EquipParamGem.xml"
    # xml_path = repo_root / "data/elden_ring_param_definitions/ShopLineupParam.xml"
    print()
    print(f"Loading {ef.underl}{xml_path}{ef.rs}")
    print()

    # Load the xml file
    tree = ET.parse(xml_path)
    root = tree.getroot()

    # Build a name -> data type mapping by parsing each field's compact Def string.
    name_to_type = {}
    for field in root.iterfind("./Fields/Field"):
        # Use iterfind() to iterate over all 'Field' elements
        field_def = field.attrib.get("Def")
        if not field_def:
            # Definition does not exist
            continue

        # Def is typically: "<type> <name>" separated by a space (and may include array/bitfield/default syntax).
        type_and_name = field_def.split(None, 2)
        if len(type_and_name) < 2:
            continue
        
        # Extract the data type string and clean/extract field name string
        data_type = type_and_name[0]
        field_name = type_and_name[1].split("[", 1)[0].split(":", 1)[0]

        # Add element to the dictionary
        name_to_type[field_name] = data_type

    # Pretty print dictionary: puts each key/value pair on one line
    pprint.pprint(name_to_type)


if __name__ == "__main__":
    main()
