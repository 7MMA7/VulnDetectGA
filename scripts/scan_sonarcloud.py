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
        with open(file_path, 'r', errors='ignore') as f: content = f.read()
        match = re.search(r'(\w+\s+)+\**(\w+)\s*\(', func_code)
        if not match: return False
        func_name = match.group(2)
        idx = content.find(func_name + "(")
        if idx == -1: idx = content.find(func_name + " (")
        if idx == -1: return False
        pre = content[:idx]
        last_brace = pre.rfind('}')
        ins_point = last_brace + 1 if last_brace != -1 else 0
        open_brace = content.find('{', idx)
        if open_brace == -1: return False
        count = 1
        end_pos = -1
        for i in range(open_brace + 1, len(content)):
            if content[i] == '{': count += 1
            elif content[i] == '}': count -= 1
            if count == 0:
                end_pos = i + 1
                break
        if end_pos == -1: return False
        new_content = content[:ins_point] + "\n" + func_code + "\n" + content[end_pos:]
        with open(file_path, 'w') as f: f.write(new_content)
        return True
    except Exception as e:
        print(f"Patch error: {e}")
        return False

def run_scanner(repo_path, branch_name):
    cmd = [
        "npx", "sonar-scanner",
        f"-Dsonar.organization={SONAR_ORG}",
        f"-Dsonar.projectKey={PROJECT_KEY}",
        f"-Dsonar.sources=.",
        f"-Dsonar.host.url=https://sonarcloud.io",
        f"-Dsonar.token={SONAR_TOKEN}",
        f"-Dsonar.branch.name={branch_name}",
        "-Dsonar.scm.disabled=true",
        "-Dsonar.cpd.exclusions=**/*",
        "-Dsonar.c.file.suffixes=.c,.h",
        "-Dsonar.cpp.file.suffixes=.cpp,.hpp"
    ]
    try:
        subprocess.run(cmd, cwd=repo_path, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        print(f"Scanner failed for {branch_name}")
        return False

def fetch_issues(branch_name, file_path):
    print(f"Waiting for processing on branch {branch_name}...")
    time.sleep(10)
    for _ in range(20):
        r = requests.get(
            f"{SONAR_API_URL}/ce/component", 
            params={"component": PROJECT_KEY, "branch": branch_name}, 
            auth=(SONAR_TOKEN, '')
        )
        data = r.json()
        if not data.get('queue') and not data.get('current'):
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
        auth=(SONAR_TOKEN, '')
    )
    issues = []
    if r.status_code == 200:
        for issue in r.json().get('issues', []):
            if os.path.basename(file_path) in issue['component']:
                issues.append({
                    "rule": issue['rule'],
                    "message": issue['message'],
                    "severity": issue['severity'],
                    "line": issue.get('line')
                })
    return issues

results = []
if os.path.exists(WORKDIR): shutil.rmtree(WORKDIR)
os.makedirs(WORKDIR)

with open("chunk_00.jsonl", "r") as f:
    for line in f:
        entry = json.loads(line)
        target_str = "vuln" if entry['target'] == 1 else "fixed"
        branch_name = f"analysis-{entry['idx']}-{target_str}"
        print(f"--- Processing {branch_name} ---")
        repo_dir = os.path.join(WORKDIR, branch_name)
        if not os.path.exists(repo_dir):
            Repo.clone_from(entry['project_url'], repo_dir)
        repo = Repo(repo_dir)
        repo.git.reset('--hard')
        repo.git.checkout(entry['commit_id'])
        full_path = os.path.join(repo_dir, entry['file_path'])
        if patch_file(full_path, entry['func']):
            if run_scanner(repo_dir, branch_name):
                issues = fetch_issues(branch_name, entry['file_path'])
                results.append({
                    "idx": entry['idx'],
                    "target": entry['target'],
                    "branch": branch_name,
                    "issues": issues
                })
        shutil.rmtree(repo_dir)

with open("final_results.json", "w") as f:
    json.dump(results, f, indent=2)
