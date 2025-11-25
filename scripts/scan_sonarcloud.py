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
LOGDIR = "scanner_logs"

def patch_file(file_path, func_code):
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
        m = re.search(r'(\w+\s+)+\**(\w+)\s*\(', func_code)
        if not m:
            return False
        name = m.group(2)
        i = content.find(name + "(")
        if i == -1:
            i = content.find(name + " (")
        if i == -1:
            return False
        pre = content[:i]
        last = pre.rfind('}')
        ins = last + 1 if last != -1 else 0
        brace = content.find('{', i)
        if brace == -1:
            return False
        c = 1
        end = -1
        for k in range(brace + 1, len(content)):
            if content[k] == '{':
                c += 1
            elif content[k] == '}':
                c -= 1
            if c == 0:
                end = k + 1
                break
        if end == -1:
            return False
        new = content[:ins] + "\n" + func_code + "\n" + content[end:]
        with open(file_path, 'w') as f:
            f.write(new)
        return True
    except:
        return False

def generate_compile_commands(repo_path, rel):
    absf = os.path.abspath(os.path.join(repo_path, rel))
    data = [
        {
            "directory": os.path.abspath(repo_path),
            "command": f"gcc -c {absf}",
            "file": absf
        }
    ]
    out = os.path.join(repo_path, "compile_commands.json")
    with open(out, 'w') as f:
        json.dump(data, f)
    return out

def run_scanner(repo_path, branch_name):
    os.makedirs(LOGDIR, exist_ok=True)
    log = os.path.join(LOGDIR, f"{branch_name}.log")
    cmd = [
        "./sonar-scanner/bin/sonar-scanner",
        f"-Dsonar.organization={SONAR_ORG}",
        f"-Dsonar.projectKey={PROJECT_KEY}",
        f"-Dsonar.sources=.",
        f"-Dsonar.host.url=https://sonarcloud.io",
        f"-Dsonar.token={SONAR_TOKEN}",
        f"-Dsonar.branch.name={branch_name}",
        "-Dsonar.cfamily.compile-commands=compile_commands.json",
        "-Dsonar.scm.disabled=true",
        "-Dsonar.exclusions=**/*.xml,**/*.css,**/*.html,**/*.java,**/*.js",
        "-Dsonar.c.file.suffixes=.c,.h",
        "-Dsonar.cpp.file.suffixes=.cpp,.hpp,.cc"
    ]
    try:
        with open(log, "w") as f:
            subprocess.run(cmd, cwd=repo_path, stdout=f, stderr=f, check=True)
        return True
    except:
        return False

def fetch_issues(branch_name, file_path):
    time.sleep(5)
    for _ in range(40):
        r = requests.get(
            f"{SONAR_API_URL}/ce/component",
            params={"component": PROJECT_KEY, "branch": branch_name},
            auth=(SONAR_TOKEN, "")
        )
        d = r.json()
        if not d.get("queue") and not d.get("current"):
            break
        time.sleep(5)
    r = requests.get(
        f"{SONAR_API_URL}/issues/search",
        params={
            "componentKeys": PROJECT_KEY,
            "branch": branch_name,
            "types": "VULNERABILITY,BUG",
            "ps": 200
        },
        auth=(SONAR_TOKEN, "")
    )
    out = []
    if r.status_code == 200:
        base = os.path.basename(file_path)
        for issue in r.json().get("issues", []):
            if base in issue["component"]:
                out.append({
                    "rule": issue["rule"],
                    "message": issue["message"],
                    "severity": issue["severity"],
                    "line": issue.get("line")
                })
    return out

results = []

if os.path.exists(WORKDIR):
    shutil.rmtree(WORKDIR)
os.makedirs(WORKDIR)
os.makedirs(LOGDIR, exist_ok=True)

with open("chunk_20.jsonl", "r") as f:
    for line in f:
        try:
            e = json.loads(line)
        except:
            continue
        b = f"analysis-{e['idx']}-{'vuln' if e['target']==1 else 'fixed'}"
        repo_dir = os.path.join(WORKDIR, b)
        try:
            Repo.clone_from(e["project_url"], repo_dir)
        except:
            continue
        r = Repo(repo_dir)
        try:
            r.git.reset("--hard")
            r.git.checkout(e["commit_id"])
        except:
            continue
        path = os.path.join(repo_dir, e["file_path"])
        if patch_file(path, e["func"]):
            generate_compile_commands(repo_dir, e["file_path"])
            if run_scanner(repo_dir, b):
                issues = fetch_issues(b, e["file_path"])
                results.append({
                    "idx": e["idx"],
                    "target": e["target"],
                    "branch": b,
                    "issues": issues
                })

with open("final_results.json", "w") as f:
    json.dump(results, f)
