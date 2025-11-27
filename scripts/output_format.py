import json
import sys

results_file = sys.argv[1]
chunks_file = sys.argv[2]
out_file = sys.argv[3]

idx_map = {}
with open(chunks_file, "r") as f:
    for line in f:
        if not line.strip():
            continue
        obj = json.loads(line)
        idx = str(obj.get("idx"))
        path = obj.get("file_path")
        if idx and path:
            idx_map[idx] = path

with open(results_file, "r") as f:
    results = json.load(f)

with open(out_file, "w") as w:
    for entry in results:
        idx = str(entry.get("idx"))
        target = entry.get("target")
        issues = entry.get("issues", [])

        if idx not in idx_map:
            continue

        path = idx_map[idx].split(":", 1)[-1]
        filtered = []

        for issue in issues:
            comp = issue.get("component", "")
            if path in comp:
                issue.pop("component", None)
                filtered.append(issue)

        if filtered:
            obj = {"idx": idx, "target": target, "file_path": path, "issues": filtered}
            w.write(json.dumps(obj) + "\n")
