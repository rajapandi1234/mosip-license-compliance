import json
import sys

sbom_file = sys.argv[1]
policy_file = sys.argv[2]

with open(sbom_file) as f:
    sbom = json.load(f)

with open(policy_file) as f:
    policy = json.load(f)

allowed = set(policy.get("allowed", []))
disallowed = set(policy.get("disallowed", []))

violations = []
unknowns = []
approved = []

for pkg in sbom.get("artifacts", []):
    name = pkg.get("name")
    version = pkg.get("version")
    lic = pkg.get("resolved_license", "UNKNOWN")

    if lic in disallowed:
        violations.append(f"{name} ({version}) - {lic}")
    elif lic in allowed:
        approved.append(f"{name} ({version}) - {lic}")
    else:
        unknowns.append(f"{name} ({version}) - {lic}")

with open("compliance-summary.txt", "w") as out:
    out.write("License Compliance Summary\n")
    out.write("==========================\n\n")

    out.write("APPROVED\n---------\n")
    for a in approved:
        out.write(a + "\n")

    out.write("\nDISALLOWED (INCOMPATIBLE)\n-------------------------\n")
    for v in violations:
        out.write(v + "\n")

    out.write("\nUNKNOWN / NOT IN POLICY\n------------------------\n")
    for u in unknowns:
        out.write(u + "\n")

print("Compliance summary generated (non-blocking).")
