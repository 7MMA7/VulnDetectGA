import json
import os
import re
import time
import shutil
import subprocess
import requests
from git import Repo

SONAR_TOKEN = os.environ.get("SONAR_TOKEN")
SONAR_ORG = os.environ.get("SONAR_ORG")
PROJECT_KEY = os.environ.get("SONAR_PROJECT_KEY")
SONAR_API_URL = "https://sonarcloud.io/api"
WORKDIR = "temp_workdir"

def patch_file(file_path, func_code):
    try:
        with open(file_path, "r", errors="ignore") as f:
            content = f.read()
        match = re.search(r"(\\w+\\s+)+\\**(\\w+)\\s*\\(", func_code)
        if not match:
            return False
        func_name = match.group(2)
        idx = content.find(func_name + "(")
        if idx == -1:
            idx = content.find(func_name + " (")
        if idx == -1:
            return False
        pre = content[:idx]
        last_brace = pre.rfind("}")
        ins_point = last_brace + 1 if last_brace != -1 else 0
        open_brace = content.find("{", idx)
        if open_brace == -1:
            return False
        count = 1
        end_pos = -1
        for i in range(open_brace + 1, len(content)):
            if content[i] == "{":
                count += 1
            elif content[i] == "}":
                count -= 1
            if count == 0:
                end_pos = i + 1
                break
        if end_pos == -1:
            return False
        new_content = content[:ins_point] + "\n" + func_code + "\n" + content[end_pos:]
        with open(file_path, "w") as f:
            f.write(new_content)
        return True
    except:
        return False

def generate_mini_root(repo_dir, rel_path):
    full_file = os.path.join(repo_dir, rel_path)
    if not os.path.exists(full_file):
        return None
    mini = os.path.join(repo_dir, "analysis_src")
    if os.path.exists(mini):
        shutil.rmtree(mini)
    os.makedirs(mini)
    rel_dir = os.path.dirname(rel_path)
    dest_dir = os.path.join(mini, rel_dir)
    os.makedirs(dest_dir, exist_ok=True)
    shutil.copy(full_file, os.path.join(mini, os.path.basename(rel_path)))
    cc = [
        {
            "directory": mini,
            "command": "/usr/bin/gcc -c " + rel_path,
            "file": os.path.join(mini, os.path.basename(rel_path))
        }
    ]
    with open(os.path.join(mini, "compile_commands.json"), "w") as f:
        json.dump(cc, f, indent=2)
    return mini

def run_scanner(mini_root, branch_name):
    cmd = [
        "npx", "sonar-scanner",
        "-Dsonar.host.url=https://sonarcloud.io",
        f"-Dsonar.organization={SONAR_ORG}",
        f"-Dsonar.projectKey={PROJECT_KEY}",
        f"-Dsonar.token={SONAR_TOKEN}",
        f"-Dsonar.projectBaseDir={mini_root}",
        f"-Dsonar.branch.name={branch_name}",
        f"-Dsonar.cfamily.compile-commands={mini_root}/compile_commands.json",
        "-Dsonar.scm.disabled=true",
        "-Dsonar.c.file.suffixes=.c,.h",
        "-Dsonar.cpp.file.suffixes=.cpp,.hpp,.cc",
        "-Dsonar.cpd.exclusions=**/*"
    ]
    try:
        p = subprocess.run(
            cmd,
            cwd=mini_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        log_path = os.path.join(mini_root, "scanner_output.txt")
        with open(log_path, "w") as f:
            f.write("STDOUT\n")
            f.write(p.stdout)
            f.write("\n\nSTDERR\n")
            f.write(p.stderr)
        return p.returncode == 0
    except:
        return False

def fetch_issues(branch_name, file_path):
    time.sleep(5)
    for _ in range(30):
        r = requests.get(
            f"{SONAR_API_URL}/ce/component",
            params={"component": PROJECT_KEY, "branch": branch_name},
            auth=(SONAR_TOKEN, "")
        )
        data = r.json()
        if not data.get("queue") and not data.get("current"):
            break
        time.sleep(5)
    r = requests.get(
        f"{SONAR_API_URL}/issues/search",
        params={
            "componentKeys": PROJECT_KEY,
            "branch": branch_name,
            "types": "VULNERABILITY,BUG",
            "ps": 100
        },
        auth=(SONAR_TOKEN, "")
    )
    if r.status_code != 200:
        return []
    issues = []
    for issue in r.json().get("issues", []):
        if os.path.basename(file_path) in issue["component"]:
            issues.append({
                "rule": issue["rule"],
                "message": issue["message"],
                "severity": issue["severity"],
                "line": issue.get("line")
            })
    return issues

if os.path.exists(WORKDIR):
    shutil.rmtree(WORKDIR)
os.makedirs(WORKDIR)

results = []

with open("chunk_20.jsonl", "r") as f:
    for line in f:
        try:
            entry = json.loads(line)
        except:
            continue

        branch_name = f"analysis-{entry['idx']}-{'vuln' if entry['target']==1 else 'fixed'}"
        repo_dir = os.path.join(WORKDIR, branch_name)

        try:
            Repo.clone_from(entry["project_url"], repo_dir)
        except:
            continue

        repo = Repo(repo_dir)
        try:
            repo.git.reset("--hard")
            repo.git.checkout(entry["commit_id"])
        except:
            continue

        full_path = os.path.join(repo_dir, entry["file_path"])
        if not patch_file(full_path, entry["func"]):
            if os.path.exists(repo_dir):
                shutil.rmtree(repo_dir)
            continue

        mini_root = generate_mini_root(repo_dir, entry["file_path"])
        if mini_root is None:
            if os.path.exists(repo_dir):
                shutil.rmtree(repo_dir)
            continue

        scan_ok = run_scanner(mini_root, branch_name)
        log_path = os.path.join(mini_root, "scanner_output.txt")

        if scan_ok:
            issues = fetch_issues(branch_name, entry["file_path"])
        else:
            issues = []

        results.append({
            "idx": entry["idx"],
            "target": entry["target"],
            "branch": branch_name,
            "issues": issues,
            "scanner_log": log_path
        })

with open("final_results.json", "w") as f:
    json.dump(results, f, indent=2)
