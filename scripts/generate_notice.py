import json
import os
import shutil
from collections import defaultdict

# Input files
sbom_file = "sbom-clean.json"
policy_file = "policy.json"

# License text folders
licenses_source = "licenses_text"
licenses_output = "licenses"

# Load SBOM
with open(sbom_file) as f:
    sbom = json.load(f)

# Load policy
with open(policy_file) as f:
    policy = json.load(f)

# Policy rules
notice_required = set(policy.get("notice_required", []))
allowed = set(policy.get("allowed", []))
restricted = set(policy.get("restricted", []))
forbidden = set(policy.get("forbidden", []))

# Prepare folders
os.makedirs(licenses_output, exist_ok=True)

# Data structures
license_packages = defaultdict(list)
used_licenses = set()
notice_licenses_used = set()

# Collect package information
for pkg in sbom.get("artifacts", []):
    name = pkg.get("name", "UNKNOWN")
    version = pkg.get("version", "UNKNOWN")
    lic = pkg.get("resolved_license", "UNKNOWN")

    used_licenses.add(lic)
    license_packages[lic].append(f"{name} ({version})")

    if lic in notice_required:
        notice_licenses_used.add(lic)

# Determine risk levels
license_risk = {}

for lic in used_licenses:
    if lic in forbidden:
        license_risk[lic] = "HIGH"
    elif lic in restricted:
        license_risk[lic] = "MEDIUM"
    elif lic in allowed:
        license_risk[lic] = "LOW"
    else:
        license_risk[lic] = "UNKNOWN"

# Generate THIRD-PARTY-NOTICES
with open("THIRD-PARTY-NOTICES.txt", "w") as tp:
    tp.write("THIRD-PARTY-NOTICES\n")
    tp.write("===================\n\n")
    tp.write("This product includes third-party software components.\n\n")

    for lic in sorted(license_packages):
        tp.write("=================================================================\n")
        tp.write(f"License: {lic}\n")
        tp.write("Packages:\n")

        for pkg in sorted(license_packages[lic]):
            tp.write(f"  - {pkg}\n")

        tp.write("=================================================================\n\n")

# Generate NOTICE file
with open("NOTICE", "w") as notice:
    notice.write("NOTICE\n")
    notice.write("======\n\n")
    notice.write("This product includes third-party software.\n\n")

    if notice_licenses_used:
        notice.write("The following licenses require attribution:\n\n")

        for lic in sorted(notice_licenses_used):
            notice.write(f"- {lic}\n")

    else:
        notice.write("No licenses require additional notice attribution.\n")

# Generate LICENSE-RISK-REPORT
with open("LICENSE-RISK-REPORT.txt", "w") as report:
    report.write("LICENSE RISK REPORT\n")
    report.write("===================\n\n")

    for lic in sorted(license_packages):
        risk = license_risk.get(lic, "UNKNOWN")

        report.write(f"License: {lic}\n")
        report.write(f"Risk Level: {risk}\n")
        report.write("Packages:\n")

        for pkg in sorted(license_packages[lic]):
            report.write(f"  - {pkg}\n")

        report.write("\n")

# Copy license text files
for lic in used_licenses:
    src = os.path.join(licenses_source, f"{lic}.txt")
    dst = os.path.join(licenses_output, f"{lic}.txt")

    if os.path.exists(src):
        shutil.copyfile(src, dst)

print("License compliance artifacts generated successfully.")
