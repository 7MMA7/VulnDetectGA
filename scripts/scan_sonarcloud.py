import json
import os
import re
import time
import shutil
import subprocess
import requests
from git import Repo
import sys

SONAR_TOKEN = os.environ.get("SONAR_TOKEN")
SONAR_ORG = os.environ.get("SONAR_ORG")
PROJECT_KEY = os.environ.get("SONAR_PROJECT_KEY")
SONAR_API_URL = "https://sonarcloud.io/api"
WORKDIR = "temp_workdir"

def patch_file(file_path, func_code):
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()
        match = re.search(r'(\w+\s+)+\**(\w+)\s*\(', func_code)
        if not match:
            return False
        func_name = match.group(2)
        idx = content.find(func_name + "(")
        if idx == -1:
            idx = content.find(func_name + " (")
        if idx == -1:
            return False
        pre = content[:idx]
        last_brace = pre.rfind('}')
        ins_point = last_brace + 1 if last_brace != -1 else 0
        open_brace = content.find('{', idx)
        if open_brace == -1:
            return False
        count = 1
        end_pos = -1
        for i in range(open_brace + 1, len(content)):
            if content[i] == '{':
                count += 1
            elif content[i] == '}':
                count -= 1
            if count == 0:
                end_pos = i + 1
                break
        if end_pos == -1:
            return False
        new_content = content[:ins_point] + "\n" + func_code + "\n" + content[end_pos:]
        with open(file_path, 'w') as f:
            f.write(new_content)
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
    with open(json_path, "w") as f:
        json.dump(commands, f, indent=2)
    return json_path

def run_scanner(repo_path, branch_name, source_dir):
    cmd = [
        "npx", "sonar-scanner",
        f"-Dsonar.organization={SONAR_ORG}",
        f"-Dsonar.projectKey={PROJECT_KEY}",
        f"-Dsonar.sources={source_dir}",
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
        subprocess.run(cmd, cwd=repo_path, check=True)
        return True
    except subprocess.CalledProcessError:
        print(f"Scanner failed for {branch_name}")
        return False

def fetch_issues(branch_name):
    time.sleep(5)
    for _ in range(40):
        r = requests.get(
            f"{SONAR_API_URL}/ce/component",
            params={"component": PROJECT_KEY, "branch": branch_name},
            auth=(SONAR_TOKEN, '')
        )
        try:
            data = r.json()
            if not data.get('queue') and not data.get('current'):
                break
        except:
            pass
        time.sleep(5)
    all_findings = []
    r_issues = requests.get(
        f"{SONAR_API_URL}/issues/search",
        params={"componentKeys": PROJECT_KEY, "branch": branch_name,
                "types": "VULNERABILITY,BUG,CODE_SMELL", "ps": 500},
        auth=(SONAR_TOKEN, '')
    )
    if r_issues.status_code == 200:
        for issue in r_issues.json().get('issues', []):
            all_findings.append({
                "type": issue['type'],
                "rule": issue['rule'],
                "message": issue['message'],
                "severity": issue['severity'],
                "component": issue['component'],
                "line": issue.get('line')
            })
    r_hotspots = requests.get(
        f"{SONAR_API_URL}/hotspots/search",
        params={"projectKey": PROJECT_KEY, "branch": branch_name, "ps": 500},
        auth=(SONAR_TOKEN, '')
    )
    if r_hotspots.status_code == 200:
        for h in r_hotspots.json().get('hotspots', []):
            all_findings.append({
                "type": "SECURITY_HOTSPOT",
                "rule": h['ruleKey'],
                "message": h['message'],
                "severity": h.get('vulnerabilityProbability', 'UNKNOWN'),
                "component": h['component'],
                "line": h.get('line')
            })
    return all_findings

if len(sys.argv) > 1:
    chunks_file = sys.argv[1]
else:
    chunks_file = "chunks/chunk_01.jsonl"

if not os.path.exists(chunks_file):
    print(f"{chunks_file} not found")
    exit(1)

if os.path.exists(WORKDIR):
    shutil.rmtree(WORKDIR)
os.makedirs(WORKDIR)

results = []

with open(chunks_file, "r") as f:
    for line in f:
        try:
            entry = json.loads(line)
        except:
            continue
        target_str = "vuln" if entry['target'] == 1 else "fixed"
        run_id = os.environ.get("GITHUB_RUN_ID", "local")
        branch_name = f"analysis-{entry['idx']}-{target_str}-{run_id}"
        print(f"--- Processing {branch_name} ---")
        repo_dir = os.path.join(WORKDIR, branch_name)
        if not os.path.exists(repo_dir):
            try:
                Repo.clone_from(entry['project_url'], repo_dir)
            except Exception as e:
                print(f"Clone error: {e}")
                continue
        repo = Repo(repo_dir)
        try:
            repo.git.reset('--hard')
            repo.git.checkout(entry['commit_id'])
        except Exception as e:
            print(f"Checkout error: {e}")
            continue
        full_path = os.path.join(repo_dir, entry['file_path'])
        source_dir = os.path.dirname(entry['file_path']) or "."
        if patch_file(full_path, entry['func']):
            generate_compile_commands(repo_dir)
            if run_scanner(repo_dir, branch_name, source_dir):
                findings = fetch_issues(branch_name)
                results.append({
                    "idx": entry['idx'],
                    "target": entry['target'],
                    "branch": branch_name,
                    "scanned_dir": source_dir,
                    "issues": findings
                })
        if os.path.exists(repo_dir):
            shutil.rmtree(repo_dir)

with open("final_results.json", "w") as f:
    json.dump(results, f, indent=2)

