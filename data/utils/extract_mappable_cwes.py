#!/usr/bin/env python3

import csv
import xml.etree.ElementTree as ET
from pathlib import Path

XML_FILE = "/home/emsha/projects/vuln_repair_pattern_mining/data/cwec_v4.20.xml"
OUTPUT_FILE = "/home/emsha/projects/vuln_repair_pattern_mining/data/utils/mappable_cwes.csv"


def get_namespace(root):
    """Extract the XML namespace."""
    if root.tag.startswith("{"):
        return {"cwe": root.tag.split("}")[0][1:]}
    return {"cwe": ""}


def get_text(element):
    """Safely return an element's text."""
    if element is None or element.text is None:
        return ""
    return element.text.strip()


def main():

    tree = ET.parse(XML_FILE)
    root = tree.getroot()

    ns = get_namespace(root)

    weaknesses = root.findall(".//cwe:Weakness", ns)

    print(f"Found {len(weaknesses)} weaknesses.")

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as csvfile:

        writer = csv.writer(csvfile)

        writer.writerow([
            "CWE_ID",
            "Name",
            "Abstraction",
            "Structure",
            "Status",
            "Mapping_Status",
            "Description"
        ])

        for weakness in weaknesses:

            cwe_id = weakness.get("ID", "")
            name = weakness.get("Name", "")
            abstraction = weakness.get("Abstraction", "")
            structure = weakness.get("Structure", "")
            status = weakness.get("Status", "")

            description = get_text(
                weakness.find("cwe:Description", ns)
            )

            # Default if no mapping notes exist
            mapping_status = ""

            mapping_notes = weakness.find("cwe:Mapping_Notes", ns)

            if mapping_notes is not None:

                usage = mapping_notes.find("cwe:Usage", ns)

                if usage is not None:
                    mapping_status = get_text(usage)
            if mapping_status == "Allowed":
                writer.writerow([
                    cwe_id,
                    name,
                    abstraction,
                    structure,
                    status,
                    mapping_status,
                    description
                ])

    print(f"Wrote {OUTPUT_FILE}")


if __name__ == "__main__":
    main()