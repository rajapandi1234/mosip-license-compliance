import json
import sys
from collections import Counter

sbom_file = sys.argv[1]
output_file = sys.argv[2]

with open(sbom_file) as f:
    sbom = json.load(f)

licenses = [
    pkg.get("resolved_license", "UNKNOWN")
    for pkg in sbom.get("artifacts", [])
]

counts = Counter(licenses)

with open(output_file, "w") as f:
    f.write("License Count Report\n")
    f.write("====================\n\n")
    for lic, count in sorted(counts.items()):
        f.write(f"{lic}: {count}\n")

print("License count report generated.")
