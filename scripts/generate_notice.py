import json
import os
import shutil

sbom_file = "sbom-clean.json"
policy_file = "policy.json"
licenses_source = "licenses_text"
licenses_output = "licenses"

with open(sbom_file) as f:
    sbom = json.load(f)

with open(policy_file) as f:
    policy = json.load(f)

notice_required = set(policy.get("notice_required", []))

os.makedirs(licenses_output, exist_ok=True)

used_licenses = set()
notice_licenses_used = set()

with open("THIRD-PARTY-NOTICES.txt", "w") as tp:
    tp.write("Third Party Dependencies\n")
    tp.write("========================\n\n")

    for pkg in sbom.get("artifacts", []):
        name = pkg.get("name")
        version = pkg.get("version")
        lic = pkg.get("resolved_license", "UNKNOWN")

        used_licenses.add(lic)
        tp.write(f"{name} ({version}) - {lic}\n")

        if lic in notice_required:
            notice_licenses_used.add(lic)

with open("NOTICE", "w") as notice:
    notice.write("NOTICE\n======\n\n")
    notice.write("This product includes third-party software.\n\n")

    if notice_licenses_used:
        notice.write("The following licenses require attribution:\n\n")
        for lic in sorted(notice_licenses_used):
            notice.write(f"- {lic}\n")
    else:
        notice.write("No licenses require additional notice attribution.\n")

for lic in used_licenses:
    src = os.path.join(licenses_source, f"{lic}.txt")
    dst = os.path.join(licenses_output, f"{lic}.txt")

    if os.path.exists(src):
        shutil.copyfile(src, dst)

print("Notices and license texts generated.")
