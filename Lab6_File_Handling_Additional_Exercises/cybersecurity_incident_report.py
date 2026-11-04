import csv
import json
import shutil
import zipfile
from collections import Counter
from pathlib import Path


WORK_DIR = Path(__file__).resolve().parent
LAST_NAME = "Adonis"
STUDENT_ID = "TUPM-26-1828"
SEED_DIGIT = int(STUDENT_ID[-1])
ID_SUM = sum(int(digit) for digit in STUDENT_ID if digit.isdigit())
TARGET_YEAR = 2015 + SEED_DIGIT

DATA_DIR = WORK_DIR / "data"
OUTPUT_DIR = WORK_DIR / "output" / "cybersecurity_incident_report"
BACKUP_DIR = WORK_DIR / "backup" / "cybersecurity_incident_report"
for folder in (DATA_DIR, OUTPUT_DIR, BACKUP_DIR):
    folder.mkdir(parents=True, exist_ok=True)

dataset_url = (
    "https://www.kaggle.com/api/v1/datasets/download/"
    "atharvasoundankar/global-cybersecurity-threats-2015-2024"
)
archive_path = DATA_DIR / "global-cybersecurity-threats-dataset.zip"
dataset_path = DATA_DIR / "Global_Cybersecurity_Threats_2015-2024.csv"
if not archive_path.exists():
    from urllib.request import urlretrieve

    urlretrieve(dataset_url, archive_path)
if not dataset_path.exists():
    with zipfile.ZipFile(archive_path) as archive:
        with archive.open(dataset_path.name) as source:
            with open(dataset_path, "wb") as destination:
                shutil.copyfileobj(source, destination)

filtered_csv_path = OUTPUT_DIR / f"{LAST_NAME}_{STUDENT_ID}_{TARGET_YEAR}_incidents.csv"
summary_json_path = OUTPUT_DIR / f"{LAST_NAME}_{STUDENT_ID}_{TARGET_YEAR}_summary.json"
backup_json_path = BACKUP_DIR / summary_json_path.name
findings_archive_path = BACKUP_DIR / f"{LAST_NAME}_{STUDENT_ID}_{TARGET_YEAR}_findings.zip"
report_path = OUTPUT_DIR / f"{LAST_NAME}_{STUDENT_ID}_{TARGET_YEAR}_report.txt"

attack_type_counts = Counter()
total_dataset_records = 0
records_in_target_year = 0
invalid_records = 0
total_financial_loss = 0.0
target_incidents = []
loss_field = "Financial Loss (in Million $)"
export_fields = ["Country", "Year", "Attack Type", "Target Industry", loss_field]

with open(dataset_path, "r", encoding="utf-8-sig", newline="") as source:
    reader = csv.DictReader(source)
    if not reader.fieldnames or not set(export_fields).issubset(reader.fieldnames):
        raise ValueError(f"Unexpected dataset columns: {reader.fieldnames}")

    with open(filtered_csv_path, "w", encoding="utf-8", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=export_fields)
        writer.writeheader()
        for row in reader:
            total_dataset_records += 1
            try:
                year = int(row["Year"].strip())
            except (AttributeError, ValueError):
                invalid_records += 1
                continue
            if year != TARGET_YEAR:
                continue

            try:
                financial_loss = float(row[loss_field].strip())
                attack_type = row["Attack Type"].strip()
                if not attack_type:
                    raise ValueError("Missing attack type")
            except (AttributeError, ValueError):
                invalid_records += 1
                continue

            incident = {field: row[field] for field in export_fields}
            incident["Year"] = year
            incident[loss_field] = financial_loss
            records_in_target_year += 1
            total_financial_loss += financial_loss
            attack_type_counts[attack_type] += 1
            target_incidents.append(incident)
            writer.writerow({field: incident[field] for field in export_fields})

average_financial_loss = (
    total_financial_loss / records_in_target_year if records_in_target_year else 0.0
)
top_five_incidents = sorted(
    target_incidents,
    key=lambda incident: -incident[loss_field],
)[:5]
with open(filtered_csv_path, "r", encoding="utf-8", newline="") as exported_file:
    exported_record_count = sum(1 for _ in csv.DictReader(exported_file))
count_verified = exported_record_count == records_in_target_year
if not count_verified:
    raise ValueError("Exported CSV row count does not match the target-year count.")

summary = {
    "last_name": LAST_NAME,
    "student_id": STUDENT_ID,
    "seed_digit": SEED_DIGIT,
    "target_year": TARGET_YEAR,
    "total_dataset_records": total_dataset_records,
    "records_in_target_year": records_in_target_year,
    "invalid_records_skipped": invalid_records,
    "attack_type_counts": dict(sorted(attack_type_counts.items())),
    "total_financial_loss_million_dollars": total_financial_loss,
    "average_financial_loss_million_dollars": average_financial_loss,
    "top_five_costliest_incidents": top_five_incidents,
    "incidents": target_incidents,
    "exported_csv_record_count": exported_record_count,
    "count_verified": count_verified,
    "filtered_csv_file": str(filtered_csv_path.relative_to(WORK_DIR)),
    "summary_json_file": str(summary_json_path.relative_to(WORK_DIR)),
    "backup_json_file": str(backup_json_path.relative_to(WORK_DIR)),
    "report_file": str(report_path.relative_to(WORK_DIR)),
    "findings_archive_file": str(findings_archive_path.relative_to(WORK_DIR)),
}
with open(summary_json_path, "w", encoding="utf-8") as summary_file:
    json.dump(summary, summary_file, indent=4)

shutil.copy2(summary_json_path, backup_json_path)
backup_verified = (
    backup_json_path.exists()
    and summary_json_path.read_bytes() == backup_json_path.read_bytes()
)
if not backup_verified:
    raise OSError("JSON summary backup could not be verified.")

with open(report_path, "w", encoding="utf-8") as report:
    report.write("CYBERSECURITY INCIDENT REPORT\n")
    report.write(f"Student: {LAST_NAME} ({STUDENT_ID})\n")
    report.write(f"Target year: {TARGET_YEAR}\n")
    report.write(f"Total dataset records: {total_dataset_records}\n")
    report.write(f"Incidents in target year: {records_in_target_year}\n")
    report.write(f"Invalid target-year records skipped: {invalid_records}\n")
    report.write("Attack counts:\n")
    for attack_type, count in sorted(attack_type_counts.items()):
        report.write(f"  {attack_type}: {count}\n")
    report.write(f"Total financial loss (USD millions): {total_financial_loss:.2f}\n")
    report.write(f"Average financial loss (USD millions): {average_financial_loss:.2f}\n")
    report.write("Five costliest incidents:\n")
    for rank, incident in enumerate(top_five_incidents, start=1):
        report.write(
            f"  {rank}. {incident['Country']} | {incident['Attack Type']} | "
            f"{incident['Target Industry']} | "
            f"${incident[loss_field]:.2f} million\n"
        )
    report.write(f"Filtered CSV: {filtered_csv_path.name} ({filtered_csv_path.stat().st_size} bytes)\n")
    report.write(f"JSON summary: {summary_json_path.name} ({summary_json_path.stat().st_size} bytes)\n")
    report.write(f"JSON backup: {backup_json_path.name} ({backup_json_path.stat().st_size} bytes)\n")
    report.write(f"JSON backup verified: {backup_verified}\n")
    report.write(f"Findings archive: {findings_archive_path.name}\n")

with zipfile.ZipFile(findings_archive_path, "w", compression=zipfile.ZIP_DEFLATED) as findings_archive:
    for path in (filtered_csv_path, summary_json_path, report_path):
        findings_archive.write(path, arcname=path.name)
    findings_archive.write(
        backup_json_path,
        arcname=f"backup/{backup_json_path.name}",
    )

with zipfile.ZipFile(findings_archive_path, "r") as findings_archive:
    archived_files = set(findings_archive.namelist())
expected_archive_files = {
    filtered_csv_path.name,
    summary_json_path.name,
    f"backup/{backup_json_path.name}",
    report_path.name,
}
archive_verified = archived_files == expected_archive_files
if not archive_verified:
    raise OSError("The findings archive is missing one or more output files.")

print("Target year:", TARGET_YEAR)
print("Total dataset records:", total_dataset_records)
print("Incidents in target year:", records_in_target_year)
print("Invalid target-year records skipped:", invalid_records)
print("Attack counts:", dict(sorted(attack_type_counts.items())))
print("Total financial loss (USD millions):", round(total_financial_loss, 2))
print("Average financial loss (USD millions):", round(average_financial_loss, 2))
print("Five costliest incidents:")
for rank, incident in enumerate(top_five_incidents, start=1):
    print(
        f"{rank}. {incident['Country']} | {incident['Attack Type']} | "
        f"{incident['Target Industry']} | ${incident[loss_field]:.2f} million"
    )
print("Filtered CSV:", filtered_csv_path)
print("JSON summary:", summary_json_path)
print("JSON backup verified:", backup_verified, f"({backup_json_path.stat().st_size} bytes)")
print("Report:", report_path)
print("Findings archive verified:", archive_verified)
