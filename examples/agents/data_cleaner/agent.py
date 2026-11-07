"""A well-behaved demo agent: summarise a CSV that ships with it and write a report to its workspace."""
import csv
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
rows = list(csv.DictReader(open(os.path.join(HERE, "sales.csv"))))
total = sum(float(r["amount"]) for r in rows)
by_region = {}
for r in rows:
    by_region[r["region"]] = by_region.get(r["region"], 0) + float(r["amount"])
with open("report.json", "w") as f:  # cwd is the agent's workspace
    json.dump({"rows": len(rows), "total": total, "by_region": by_region}, f, indent=2)
print(f"wrote report.json: {len(rows)} rows, total {total:.2f}")
