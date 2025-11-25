import jsonlines
import subprocess
import tempfile
import shutil
import requests
import time
import os
import sys

SONAR_TOKEN = os.environ["SONAR_TOKEN"]
SONAR_ORG = os.environ["SONAR_ORGANIZATION"]
BASE_PROJECT_KEY = os.environ["SONAR_PROJECT_KEY"]
API_URL = "https://sonarcloud.io/api"

def run(cmd, cwd=None):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr)
    return r.stdout

def wait_for_ce(task_id):
    url = f"{API_URL}/ce/task?id={task_id}"
    for _ in range(40):
        r = requests.get(url, auth=(SONAR_TOKEN, ""))
        status = r.json()["task"]["status"]
        if status in ["SUCCESS", "FAILED"]:
            return status
        time.sleep(2)
    return "TIMEOUT"

def extract_issue_fields(i):
    return {
        "rule": i.get("rule"),
        "severity": i.get("severity"),
        "message": i.get("message"),
        "cwe": i.get("cwe"),
        "cve": i.get("cve")
    }

def scan_commit(repo_url, commit_id):
    tmp = tempfile.mkdtemp()
    try:
        run(["git", "clone", "--depth", "1", repo_url, tmp])
        run(["git", "fetch", "--depth", "1", "origin", commit_id], cwd=tmp)
        run(["git", "checkout", commit_id], cwd=tmp)
        project_key = f"{BASE_PROJECT_KEY}_{commit_id[:8]}"
        out = subprocess.run(
            [
                "sonar-scanner",
                f"-Dsonar.organization={SONAR_ORG}",
                f"-Dsonar.projectKey={project_key}",
                f"-Dsonar.sources=.",
                f"-Dsonar.host.url=https://sonarcloud.io",
                f"-Dsonar.login={SONAR_TOKEN}",
            ],
            cwd=tmp,
            capture_output=True,
            text=True
        )
        task_id = None
        for line in out.stdout.splitlines():
            if "ce/task?id=" in line:
                task_id = line.split("ce/task?id=")[1].strip()
                break
        if not task_id:
            return None, "scan"
        status = wait_for_ce(task_id)
        if status != "SUCCESS":
            return None, "scan"
        r = requests.get(f"{API_URL}/issues/search?componentKeys={project_key}", auth=(SONAR_TOKEN, ""))
        issues = r.json().get("issues", [])
        return [extract_issue_fields(i) for i in issues], None
    finally:
        shutil.rmtree(tmp)

def main(in_file, out_file):
    with jsonlines.open(in_file) as reader, jsonlines.open(out_file, "w") as writer:
        for entry in reader:
            idx = entry["idx"]
            repo = entry["project_url"]
            commit = entry["commit_id"]
            try:
                issues, err = scan_commit(repo, commit)
                writer.write({"idx": idx, "issues": issues, "error": err})
            except Exception as e:
                writer.write({"idx": idx, "issues": None, "error": str(e)})

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])

