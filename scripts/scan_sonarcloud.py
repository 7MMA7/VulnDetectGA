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

def generate_compile_commands(repo_path):
    sources = []
    include_dirs = set()
    for root, dirs, files in os.walk(repo_path):
        for f in files:
            if f.endswith((".c", ".cpp", ".cc")):
                rel_path = os.path.relpath(os.path.join(root, f), repo_path)
                sources.append(rel_path)
            if f.endswith((".h", ".hpp")):
                include_dirs.add(os.path.relpath(root, repo_path))
    commands = []
    for src in sources:
        inc_flags = " ".join(f"-I{d}" for d in include_dirs)
        abs_src = os.path.abspath(os.path.join(repo_path, src))
        commands.append({
            "directory": os.path.abspath(repo_path),
            "command": f"gcc -c {src} {inc_flags}",
            "file": abs_src
        })
    json_path = os.path.join(repo_path, "compile_commands.json")
    with open(json_path, "w") as f: json.dump(commands, f, indent=2)
    return json_path

def run_scanner(repo_path, branch_name):
    cmd = [
        "npx", "sonar-scanner",
        f"-Dsonar.organization={SONAR_ORG}",
        f"-Dsonar.projectKey={PROJECT_KEY}",
        f"-Dsonar.sources=.",
        f"-Dsonar.host.url=https://sonarcloud.io",
        f"-Dsonar.token={SONAR_TOKEN}",
        f"-Dsonar.branch.name={branch_name}",
        "-Dsonar.cfamily.compile-commands=compile_commands.json",
        "-Dsonar.scm.disabled=true",
        "-Dsonar.cpd.exclusions=**/*",
        "-Dsonar.exclusions=**/*.xml,**/*.css,**/*.html,**/*.java,**/*.js",
        "-Dsonar.c.file.suffixes=.c,.h",
        "-Dsonar.cpp.file.suffixes=.cpp,.hpp,.cc"
    ]
    try:
        subprocess.run(cmd, cwd=repo_path, check=True, stdout=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        print(f"Scanner failed for {branch_name}")
        return False

def fetch_issues(branch_name, file_path):
    print(f"Waiting for results on {branch_name}...")
    time.sleep(5)
    for _ in range(30):
        r = requests.get(f"{SONAR_API_URL}/ce/component", params={"component": PROJECT_KEY, "branch": branch_name}, auth=(SONAR_TOKEN, ''))
        data = r.json()
        if not data.get('queue') and not data.get('current'): break
        time.sleep(5)
    r = requests.get(f"{SONAR_API_URL}/issues/search", params={"componentKeys": PROJECT_KEY,"branch": branch_name,"types": "VULNERABILITY,BUG","ps": 100}, auth=(SONAR_TOKEN, ''))
    issues = []
    if r.status_code == 200:
        for issue in r.json().get('issues', []):
            if os.path.basename(file_path) in issue['component']:
                issues.append({"rule": issue['rule'], "message": issue['message'], "severity": issue['severity'], "line": issue.get('line')})
    return issues

results = []
if os.path.exists(WORKDIR): shutil.rmtree(WORKDIR)
os.makedirs(WORKDIR)

input_file = "chunk_19.jsonl"
if not os.path.exists(input_file):
    print(f"{input_file} not found")
    exit(1)

with open(input_file, "r") as f:
    for line in f:
        try: entry = json.loads(line)
        except: continue
        target_str = "vuln" if entry['target'] == 1 else "fixed"
        branch_name = f"analysis-{entry['idx']}-{target_str}"
        print(f"--- Processing {branch_name} ---")
        repo_dir = os.path.join(WORKDIR, branch_name)
        if not os.path.exists(repo_dir):
            try: Repo.clone_from(entry['project_url'], repo_dir)
            except: continue
        repo = Repo(repo_dir)
        try:
            repo.git.reset('--hard')
            repo.git.checkout(entry['commit_id'])
        except: continue
        full_path = os.path.join(repo_dir, entry['file_path'])
        if patch_file(full_path, entry['func']):
            generate_compile_commands(repo_dir)
            if run_scanner(repo_dir, branch_name):
                issues = fetch_issues(branch_name, entry['file_path'])
                results.append({"idx": entry['idx'], "target": entry['target'], "branch": branch_name, "issues": issues})
        if os.path.exists(repo_dir): shutil.rmtree(repo_dir)

with open("final_results.json", "w") as f: json.dump(results, f, indent=2)
