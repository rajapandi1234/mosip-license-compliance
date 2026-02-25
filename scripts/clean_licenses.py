import json
import sys

input_file = sys.argv[1]
output_file = sys.argv[2]

with open(input_file) as f:
    sbom = json.load(f)

for pkg in sbom.get("artifacts", []):
    licenses = pkg.get("licenses", [])
    resolved = "UNKNOWN"

    if licenses:
        raw = licenses[0].get("value", "").strip()

        if " OR " in raw:
            resolved = raw.split(" OR ")[0].strip()
        elif " AND " in raw:
            resolved = raw.split(" AND ")[0].strip()
        else:
            resolved = raw.strip()

    pkg["resolved_license"] = resolved

with open(output_file, "w") as f:
    json.dump(sbom, f, indent=2)

print("License normalization completed.")
