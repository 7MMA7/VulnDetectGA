import os, sys, tempfile, shutil, time, jsonlines, requests
from git import Repo
import subprocess

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
        Repo.clone_from(repo_url, tmp, depth=1)
        repo = Repo(tmp)
        repo.git.fetch("origin", commit_id, depth=1)
        repo.git.checkout(commit_id)

        out = run([
            "sonar-scanner",
            f"-Dsonar.organization={SONAR_ORG}",
            f"-Dsonar.projectKey={BASE_PROJECT_KEY}",
            "-Dsonar.sources=.",
            "-Dsonar.host.url=https://sonarcloud.io",
            f"-Dsonar.login={SONAR_TOKEN}"
        ], cwd=tmp)

        task_id = None
        for line in out.splitlines():
            if "ce/task?id=" in line:
                task_id = line.split("ce/task?id=")[1].strip()
                break
        if not task_id:
            return None, "scan"

        status = wait_for_ce(task_id)
        if status != "SUCCESS":
            return None, "scan"

        r = requests.get(f"{API_URL}/issues/search?componentKeys={BASE_PROJECT_KEY}&types=VULNERABILITY", auth=(SONAR_TOKEN,""))
        issues = r.json().get("issues", [])
        return [extract_issue_fields(i) for i in issues], None
    finally:
        shutil.rmtree(tmp)

def main(in_file, out_file):
    with jsonlines.open(in_file) as reader, jsonlines.open(out_file, "w") as writer:
        for entry in reader:
            idx = entry["idx"]
            try:
                issues, err = scan_commit(entry["project_url"], entry["commit_id"])
                writer.write({"idx": idx, "issues": issues, "error": err})
            except Exception as e:
                writer.write({"idx": idx, "issues": None, "error": str(e)})

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
