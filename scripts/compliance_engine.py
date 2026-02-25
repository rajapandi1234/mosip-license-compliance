import json
import re
import os
import sys
from collections import Counter

# ===========================
# LOAD SBOM
# ===========================
with open("sbom-raw.json") as f:
    sbom = json.load(f)

# ===========================
# LOAD POLICY CONFIG
# ===========================
with open("policy/mosip-mpl-policy.json") as f:
    policy = json.load(f)

ALLOWED = set(policy["allowed"])
DISALLOWED = set(policy["disallowed"])
NOTICE_REQUIRED = set(policy["notice_required"])

# ===========================
# SPDX Helpers
# ===========================

def extract_spdx_list(expression):
    if not expression:
        return []
    expression = expression.replace("(", "").replace(")", "")
    parts = re.split(r"\s+OR\s+|\s+AND\s+", expression)
    return [p.strip() for p in parts]

def choose_license(expression):
    if not expression:
        return None, "NO_LICENSE_FOUND"

    licenses = extract_spdx_list(expression)

    if " OR " in expression:
        for lic in licenses:
            if lic in ALLOWED:
                return lic, "SELECTED_FROM_OR"
        return None, "NO_COMPATIBLE_OPTION"

    if " AND " in expression:
        for lic in licenses:
            if lic in DISALLOWED:
                return None, "AND_CONTAINS_DISALLOWED"
        return expression, "AND_ALL_ALLOWED"

    lic = licenses[0]
    if lic in ALLOWED:
        return lic, "SINGLE_ALLOWED"
    if lic in DISALLOWED:
        return None, "SINGLE_DISALLOWED"

    return None, "UNKNOWN_LICENSE"

# ===========================
# Processing
# ===========================

os.makedirs("licenses", exist_ok=True)

third_party = []
unique_licenses = set()
non_compliant = []
license_counter = Counter()

for comp in sbom.get("artifacts", []):
    spdx_expression = None

    for lic in comp.get("licenses", []):
        if lic.get("spdxExpression"):
            spdx_expression = lic["spdxExpression"]
            break

    selected_license, status = choose_license(spdx_expression)

    if selected_license:
        comp["licenses"] = [{"license": {"id": selected_license}}]
        license_counter[selected_license] += 1

        if " AND " in selected_license:
            for l in extract_spdx_list(selected_license):
                unique_licenses.add(l)
        else:
            unique_licenses.add(selected_license)
    else:
        comp["licenses"] = []
        non_compliant.append({
            "name": comp.get("name"),
            "version": comp.get("version"),
            "license": spdx_expression,
            "reason": status
        })

    third_party.append({
        "name": comp.get("name", "UNKNOWN"),
        "version": comp.get("version", "UNKNOWN"),
        "original_license": spdx_expression or "UNKNOWN",
        "selected_license": selected_license or "NON-COMPLIANT",
        "status": status
    })

# ===========================
# OUTPUT FILES
# ===========================

with open("sbom-final.json", "w") as f:
    json.dump(sbom, f, indent=2)

# THIRD-PARTY-NOTICES
with open("THIRD-PARTY-NOTICES.txt", "w") as f:
    for e in third_party:
        f.write("============================================================\n")
        f.write(f"Package: {e['name']}\n")
        f.write(f"Version: {e['version']}\n")
        f.write(f"Original License: {e['original_license']}\n")
        f.write(f"Selected License (MOSIP Policy): {e['selected_license']}\n")
        f.write(f"Status: {e['status']}\n")
        f.write("============================================================\n\n")

# NOTICE FILE
with open("NOTICE", "w") as notice:
    notice.write("This product includes third-party software components.\n\n")
    for e in third_party:
        if e["selected_license"] in NOTICE_REQUIRED:
            notice.write(f"{e['name']} ({e['version']}) - {e['selected_license']}\n")

# LICENSE COUNT REPORT
with open("LICENSE-SUMMARY.txt", "w") as report:
    report.write("License Count Summary\n")
    report.write("=====================\n\n")
    for lic, count in license_counter.items():
        report.write(f"{lic}: {count}\n")

# FAIL IF NON-COMPLIANT
if non_compliant:
    print("\n❌ NON-COMPLIANT PACKAGES FOUND:\n")
    for item in non_compliant:
        print(item)
    sys.exit(1)

print("\n✅ MOSIP License Compliance Passed\n")
