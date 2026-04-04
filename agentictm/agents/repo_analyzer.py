"""GitHub/GitLab Repository Analyzer — extracts architecture via REST API.

Uses the GitHub/GitLab REST API to analyze repository structure without
cloning. Supports:
- Private repos via token authentication (Fine-grained PAT)
- Multiple repositories per analysis
- Auto-detection of repo URLs from free-form text
- Selective fetching (only architecture-relevant files)

Architecture:
    1. Detect repo URLs in text → extract owner/repo
    2. GET /repos/{owner}/{repo}/git/trees/{branch}?recursive=1 → file tree
    3. Filter to _INTERESTING_FILES patterns
    4. GET /repos/{owner}/{repo}/contents/{path} → decode Base64
    5. Extract architecture signals → system description

Usage::

    from agentictm.agents.repo_analyzer import (
        detect_repo_urls, analyze_repos_from_urls, enrich_input_with_repos
    )

    urls = detect_repo_urls("Analyze https://github.com/org/api and https://github.com/org/frontend")
    results = analyze_repos_from_urls(urls, github_token="ghp_...")
    enriched = enrich_input_with_repos("My system has two services", results)
"""

from __future__ import annotations

import base64
import json
import logging
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# URL auto-detection
# ---------------------------------------------------------------------------

# Matches: https://github.com/owner/repo, https://gitlab.com/owner/repo
# Also handles: .git suffix, /tree/branch, trailing slashes
_REPO_URL_PATTERN = re.compile(
    r'https?://(?:www\.)?'
    r'(github\.com|gitlab\.com|bitbucket\.org)'
    r'/([a-zA-Z0-9._-]+)'
    r'/([a-zA-Z0-9._-]+)'
    r'(?:\.git)?'
    r'(?:/tree/([a-zA-Z0-9._/-]+))?'
    r'(?:\s|$|[)\]},;"\'])',
    re.IGNORECASE,
)


@dataclass
class RepoInfo:
    """Parsed repository information from a URL."""
    platform: str  # "github" | "gitlab" | "bitbucket"
    owner: str
    repo: str
    branch: str = "main"
    url: str = ""


@dataclass
class RepoAnalysisResult:
    """Result of analyzing a single repository."""
    repo: RepoInfo
    system_description: str = ""
    tech_stack: list[str] = field(default_factory=list)
    files_analyzed: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    source_dirs: list[str] = field(default_factory=list)
    error: str | None = None


def detect_repo_urls(text: str) -> list[RepoInfo]:
    """Detect GitHub/GitLab/Bitbucket repository URLs in free-form text.

    Args:
        text: Any text that might contain repo URLs

    Returns:
        List of RepoInfo objects, deduplicated
    """
    repos: list[RepoInfo] = []
    seen: set[str] = set()

    for match in _REPO_URL_PATTERN.finditer(text + " "):
        platform_host = match.group(1).lower()
        owner = match.group(2)
        repo = match.group(3).rstrip(".")
        # Strip .git suffix (greedy regex captures it in the repo name)
        if repo.endswith(".git"):
            repo = repo[:-4]
        branch = match.group(4) or "main"

        # Map host to platform
        platform = "github"
        if "gitlab" in platform_host:
            platform = "gitlab"
        elif "bitbucket" in platform_host:
            platform = "bitbucket"

        key = f"{platform}/{owner}/{repo}"
        if key in seen:
            continue
        seen.add(key)

        url = f"https://{platform_host}/{owner}/{repo}"
        repos.append(RepoInfo(
            platform=platform, owner=owner, repo=repo,
            branch=branch, url=url,
        ))

    logger.info("[RepoAnalyzer] Detected %d repo URLs in input text", len(repos))
    return repos


# ---------------------------------------------------------------------------
# Files to look for, grouped by category
# ---------------------------------------------------------------------------

_INTERESTING_PATTERNS: dict[str, list[str]] = {
    "deployment": [
        "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
        "docker-compose.prod.yml", "docker-compose.production.yml",
        "k8s/", "kubernetes/", "helm/Chart.yaml",
        "terraform/", "serverless.yml", "app.yaml",
        "fly.toml", "render.yaml", "railway.json",
        "Procfile", "nixpacks.toml",
    ],
    "ci_cd": [
        ".github/workflows/", ".gitlab-ci.yml",
        "Jenkinsfile", "azure-pipelines.yml",
        ".circleci/config.yml", "bitbucket-pipelines.yml",
    ],
    "package_manifest": [
        "package.json", "requirements.txt", "pyproject.toml",
        "Pipfile", "go.mod", "Cargo.toml", "pom.xml",
        "build.gradle", "Gemfile", "composer.json",
    ],
    "api_spec": [
        "openapi.yaml", "openapi.json", "openapi.yml",
        "swagger.yaml", "swagger.json",
        "api-spec.yaml", "api-spec.json",
        "graphql/schema", "schema.graphql",
    ],
    "config": [
        ".env.example", ".env.sample", "config.json",
        "config.yaml", "config.yml",
        "appsettings.json", "application.properties",
        "application.yml", "settings.py",
    ],
    "security": [
        ".snyk", "SECURITY.md", "security.md",
        ".dependency-check-suppression.xml",
    ],
    "readme": [
        "README.md", "readme.md", "README.rst",
    ],
}


def _matches_pattern(filepath: str, patterns: list[str]) -> bool:
    """Check if a file path matches any of the patterns."""
    for pattern in patterns:
        if pattern.endswith("/"):
            # Directory prefix match
            if filepath.startswith(pattern) or f"/{pattern}" in filepath:
                return True
        else:
            # Exact file name match (anywhere in the tree)
            basename = filepath.rsplit("/", 1)[-1] if "/" in filepath else filepath
            if basename == pattern or filepath == pattern:
                return True
    return False


def _categorize_file(filepath: str) -> str | None:
    """Return the category of a file, or None if not interesting."""
    for category, patterns in _INTERESTING_PATTERNS.items():
        if _matches_pattern(filepath, patterns):
            return category
    return None


# ---------------------------------------------------------------------------
# GitHub REST API
# ---------------------------------------------------------------------------

_GITHUB_API = "https://api.github.com"
_GITLAB_API = "https://gitlab.com/api/v4"


def _api_request(
    url: str,
    token: str | None = None,
    *,
    timeout: int = 30,
    platform: str = "github",
) -> dict | list | None:
    """Make an authenticated API request."""
    headers = {"User-Agent": "AgenticTM/1.0", "Accept": "application/json"}

    if token:
        if platform == "github":
            headers["Authorization"] = f"Bearer {token}"
        elif platform == "gitlab":
            headers["PRIVATE-TOKEN"] = token

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        logger.warning("[RepoAnalyzer] API error %d for %s: %s", e.code, url, e.reason)
        if e.code == 401:
            raise PermissionError(f"Authentication failed for {url}. Check your token.")
        if e.code == 404:
            raise FileNotFoundError(f"Repository not found: {url}")
        return None
    except (urllib.error.URLError, TimeoutError) as e:
        logger.warning("[RepoAnalyzer] Request failed for %s: %s", url, e)
        return None


def _github_default_branch(
    owner: str, repo: str,
    token: str | None = None,
) -> str:
    """Return the repository's actual default branch (main, master, etc.)."""
    url = f"{_GITHUB_API}/repos/{owner}/{repo}"
    data = _api_request(url, token, platform="github")
    if data and isinstance(data, dict):
        return data.get("default_branch", "main")
    return "main"


def _fetch_github_tree(
    owner: str, repo: str, branch: str = "main",
    token: str | None = None,
) -> list[dict[str, Any]]:
    """Fetch the recursive file tree from GitHub API.

    If the requested branch is not found (404), automatically falls back to the
    repository's actual default branch (e.g. 'master' instead of 'main').
    """
    url = f"{_GITHUB_API}/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
    try:
        data = _api_request(url, token, platform="github")
    except FileNotFoundError:
        data = None  # Branch not found — will fall through to retry below

    if data and "tree" in data:
        return [
            {"path": item["path"], "type": item["type"], "size": item.get("size", 0)}
            for item in data["tree"]
            if item["type"] == "blob"
        ]

    # Branch not found — look up the real default branch and retry once
    default = _github_default_branch(owner, repo, token)
    if default != branch:
        logger.info(
            "[RepoAnalyzer] Branch '%s' not found for %s/%s, retrying with default branch '%s'",
            branch, owner, repo, default,
        )
        url = f"{_GITHUB_API}/repos/{owner}/{repo}/git/trees/{default}?recursive=1"
        try:
            data = _api_request(url, token, platform="github")
        except FileNotFoundError:
            data = None
        if data and "tree" in data:
            return [
                {"path": item["path"], "type": item["type"], "size": item.get("size", 0)}
                for item in data["tree"]
                if item["type"] == "blob"
            ]
    return []


def _fetch_github_file(
    owner: str, repo: str, path: str,
    token: str | None = None,
    *, max_size: int = 100_000,
) -> str | None:
    """Fetch a single file's content from GitHub API (Base64 decoded)."""
    url = f"{_GITHUB_API}/repos/{owner}/{repo}/contents/{path}"
    data = _api_request(url, token, platform="github")
    if not data or "content" not in data:
        return None

    # Check size
    size = data.get("size", 0)
    if size > max_size:
        logger.debug("[RepoAnalyzer] Skipping %s (size %d > %d)", path, size, max_size)
        return None

    try:
        return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
    except Exception:
        return None


def _fetch_gitlab_tree(
    owner: str, repo: str, branch: str = "main",
    token: str | None = None,
) -> list[dict[str, Any]]:
    """Fetch file tree from GitLab API."""
    project_id = urllib.request.quote(f"{owner}/{repo}", safe="")
    url = f"{_GITLAB_API}/projects/{project_id}/repository/tree?recursive=true&per_page=100&ref={branch}"
    data = _api_request(url, token, platform="gitlab")
    if data and isinstance(data, list):
        return [
            {"path": item["path"], "type": item["type"], "size": 0}
            for item in data
            if item["type"] == "blob"
        ]
    return []


def _fetch_gitlab_file(
    owner: str, repo: str, path: str,
    token: str | None = None,
) -> str | None:
    """Fetch file content from GitLab API."""
    project_id = urllib.request.quote(f"{owner}/{repo}", safe="")
    encoded_path = urllib.request.quote(path, safe="")
    url = f"{_GITLAB_API}/projects/{project_id}/repository/files/{encoded_path}/raw"
    try:
        headers = {"User-Agent": "AgenticTM/1.0"}
        if token:
            headers["PRIVATE-TOKEN"] = token
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Repo analysis core
# ---------------------------------------------------------------------------

def analyze_single_repo(
    repo: RepoInfo,
    token: str | None = None,
    *,
    max_files: int = 30,
    max_file_size: int = 80_000,
) -> RepoAnalysisResult:
    """Analyze a single repository via API.

    Args:
        repo: Repository info
        token: Auth token (GitHub PAT or GitLab token)
        max_files: Maximum interesting files to fetch
        max_file_size: Maximum file content size in bytes

    Returns:
        RepoAnalysisResult with system_description, tech_stack, findings
    """
    result = RepoAnalysisResult(repo=repo)

    try:
        # Step 1: Fetch file tree
        if repo.platform == "github":
            tree = _fetch_github_tree(repo.owner, repo.repo, repo.branch, token)
        elif repo.platform == "gitlab":
            tree = _fetch_gitlab_tree(repo.owner, repo.repo, repo.branch, token)
        else:
            result.error = f"Unsupported platform: {repo.platform}"
            return result

        if not tree:
            # For GitLab, try fetching the default branch from the project metadata
            if repo.platform == "gitlab":
                project_id = urllib.request.quote(f"{repo.owner}/{repo.repo}", safe="")
                proj_data = _api_request(f"{_GITLAB_API}/projects/{project_id}", token, platform="gitlab")
                if proj_data and isinstance(proj_data, dict):
                    default_branch = proj_data.get("default_branch", "main")
                    if default_branch != repo.branch:
                        logger.info(
                            "[RepoAnalyzer] GitLab branch '%s' not found, retrying with '%s'",
                            repo.branch, default_branch,
                        )
                        tree = _fetch_gitlab_tree(repo.owner, repo.repo, default_branch, token)
            if not tree:
                result.error = "Could not fetch repository tree (check token/branch/permissions)"
                return result

        logger.info("[RepoAnalyzer] %s/%s: %d files in tree", repo.owner, repo.repo, len(tree))

        # Step 2: Identify interesting files
        interesting: list[tuple[str, str]] = []  # (path, category)
        source_dirs: set[str] = set()

        for item in tree:
            path = item["path"]
            # Track source directories
            parts = path.split("/")
            if len(parts) >= 2 and parts[0] in ("src", "app", "lib", "api", "cmd", "pkg", "services", "internal"):
                source_dirs.add(parts[0])

            category = _categorize_file(path)
            if category and len(interesting) < max_files:
                interesting.append((path, category))

        result.source_dirs = sorted(source_dirs)

        # Step 3: Fetch file contents
        for path, category in interesting:
            if repo.platform == "github":
                content = _fetch_github_file(repo.owner, repo.repo, path, token, max_size=max_file_size)
            elif repo.platform == "gitlab":
                content = _fetch_gitlab_file(repo.owner, repo.repo, path, token)
            else:
                continue

            if content:
                result.files_analyzed.append(path)
                finding = _extract_from_file(category, path, content)
                if finding:
                    result.findings.append(finding)
                    result.tech_stack.extend(finding.get("technologies", []))

        # Deduplicate tech stack
        result.tech_stack = sorted(set(result.tech_stack))

        # Step 4: Build system description
        result.system_description = _build_system_description(
            f"{repo.owner}/{repo.repo}", result.findings, set(result.tech_stack), source_dirs,
        )

        logger.info(
            "[RepoAnalyzer] %s/%s: %d files analyzed, %d tech items found",
            repo.owner, repo.repo, len(result.files_analyzed), len(result.tech_stack),
        )

    except PermissionError as e:
        result.error = str(e)
    except FileNotFoundError as e:
        result.error = str(e)
    except Exception as e:
        result.error = f"Unexpected error: {e}"
        logger.exception("[RepoAnalyzer] Error analyzing %s/%s", repo.owner, repo.repo)

    return result


def analyze_repos_from_urls(
    repos: list[RepoInfo],
    token: str | None = None,
    *,
    max_workers: int = 3,
) -> list[RepoAnalysisResult]:
    """Analyze multiple repositories in parallel.

    Args:
        repos: List of repos to analyze
        token: Auth token (shared across all repos)
        max_workers: Max parallel API fetches

    Returns:
        List of RepoAnalysisResult, one per repo
    """
    if not repos:
        return []

    results: list[RepoAnalysisResult] = []

    with ThreadPoolExecutor(max_workers=min(max_workers, len(repos))) as pool:
        futures = {
            pool.submit(analyze_single_repo, repo, token): repo
            for repo in repos
        }
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                repo = futures[future]
                results.append(RepoAnalysisResult(
                    repo=repo, error=f"Thread error: {e}",
                ))

    return results


def enrich_input_with_repos(
    original_input: str,
    repo_results: list[RepoAnalysisResult],
) -> str:
    """Merge repository analysis results with the original user input.

    Args:
        original_input: The user's prompt text
        repo_results: Analysis results from one or more repos

    Returns:
        Enriched input combining user text + repo architecture info
    """
    if not repo_results:
        return original_input

    parts = [original_input]
    parts.append("\n\n--- Repository Analysis (auto-extracted) ---\n")

    for res in repo_results:
        if res.error:
            parts.append(f"\n[WARNING] **{res.repo.owner}/{res.repo.repo}**: {res.error}\n")
            continue

        if res.system_description:
            parts.append(f"\n{res.system_description}\n")

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Legacy git clone fallback
# ---------------------------------------------------------------------------

def analyze_repo_clone(
    repo_url: str,
    branch: str = "main",
    *,
    max_file_size: int = 50_000,
    timeout: int = 60,
) -> dict[str, Any]:
    """Fallback: Clone and analyze a Git repository (for non-GitHub/GitLab repos).

    Args:
        repo_url: HTTPS URL of the repository
        branch: Branch to analyze
        max_file_size: Max bytes to read per file
        timeout: Clone timeout in seconds

    Returns:
        Dict with system_description, components, tech_stack, files_analyzed
    """
    if not repo_url.startswith(("https://", "http://")):
        raise ValueError("Repository URL must start with https:// or http://")

    clean_url = repo_url.split("@")[-1] if "@" in repo_url else repo_url
    tmpdir = tempfile.mkdtemp(prefix="agentictm_repo_")

    try:
        logger.info("[RepoAnalyzer] Falling back to git clone for %s", clean_url)
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", branch, repo_url, tmpdir],
            capture_output=True, text=True, timeout=timeout,
        )
        if result.returncode != 0:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, tmpdir],
                capture_output=True, text=True, timeout=timeout,
            )
            if result.returncode != 0:
                raise RuntimeError(f"Git clone failed: {result.stderr[:500]}")

        repo_path = Path(tmpdir)
        findings: list[dict[str, Any]] = []
        tech_stack: set[str] = set()
        files_analyzed: list[str] = []
        src_dirs: set[str] = set()

        for item in repo_path.rglob("*"):
            if ".git" in item.parts:
                continue
            if item.is_dir() and item.name in ("src", "app", "lib", "api", "services", "cmd", "pkg"):
                src_dirs.add(str(item.relative_to(repo_path)))
            if item.is_file() and item.stat().st_size <= max_file_size:
                rel_path = str(item.relative_to(repo_path))
                category = _categorize_file(rel_path)
                if category:
                    try:
                        content = item.read_text(encoding="utf-8", errors="replace")[:max_file_size]
                        files_analyzed.append(rel_path)
                        finding = _extract_from_file(category, rel_path, content)
                        if finding:
                            findings.append(finding)
                            tech_stack.update(finding.get("technologies", []))
                    except Exception:
                        pass

        return {
            "system_description": _build_system_description(
                repo_path.name, findings, tech_stack, src_dirs,
            ),
            "tech_stack": sorted(tech_stack),
            "files_analyzed": files_analyzed,
            "source_directories": sorted(src_dirs),
            "repo_url": clean_url,
            "branch": branch,
        }
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ---------------------------------------------------------------------------
# File extraction logic (shared between API and clone paths)
# ---------------------------------------------------------------------------

def _extract_from_file(category: str, path: str, content: str) -> dict[str, Any] | None:
    """Extract relevant architecture info from a file."""
    result: dict[str, Any] = {
        "category": category,
        "file": path,
        "technologies": [],
        "summary": "",
    }

    if category == "readme":
        # Extract first 500 chars for context
        result["summary"] = content[:500].strip()
        return result

    if category == "package_manifest":
        if "package.json" in path:
            try:
                pkg = json.loads(content)
                deps = list(pkg.get("dependencies", {}).keys())[:20]
                dev_deps = list(pkg.get("devDependencies", {}).keys())[:10]
                result["technologies"] = ["Node.js"] + deps[:10]
                result["summary"] = f"Node.js project with {len(deps)} deps, {len(dev_deps)} devDeps"
                if "scripts" in pkg:
                    scripts = list(pkg["scripts"].keys())
                    result["summary"] += f". Scripts: {', '.join(scripts[:5])}"
            except json.JSONDecodeError:
                pass
        elif "requirements.txt" in path:
            deps = [line.split("==")[0].split(">=")[0].split("[")[0].strip()
                    for line in content.split("\n")
                    if line.strip() and not line.startswith("#") and not line.startswith("-")]
            result["technologies"] = ["Python"] + deps[:10]
            result["summary"] = f"Python project with {len(deps)} dependencies"
        elif "pyproject.toml" in path:
            result["technologies"] = ["Python"]
            # Extract project name if possible
            name_match = re.search(r'name\s*=\s*"([^"]+)"', content)
            result["summary"] = f"Python project: {name_match.group(1) if name_match else 'pyproject.toml'}"
        elif "go.mod" in path:
            module_match = re.search(r'^module\s+(.+)$', content, re.MULTILINE)
            result["technologies"] = ["Go"]
            result["summary"] = f"Go module: {module_match.group(1) if module_match else 'unknown'}"
        elif "Cargo.toml" in path:
            result["technologies"] = ["Rust"]
            result["summary"] = "Rust project (Cargo.toml)"
        elif "pom.xml" in path:
            result["technologies"] = ["Java", "Maven"]
            result["summary"] = "Java/Maven project"
        elif "build.gradle" in path:
            result["technologies"] = ["Java", "Gradle"]
            result["summary"] = "Java/Gradle project"
        elif "composer.json" in path:
            result["technologies"] = ["PHP", "Composer"]
            result["summary"] = "PHP/Composer project"

    elif category == "deployment":
        if "Dockerfile" in path:
            result["technologies"].append("Docker")
            for line in content.split("\n"):
                stripped = line.strip()
                if stripped.upper().startswith("FROM "):
                    result["summary"] = f"Docker: {stripped}"
                    # Infer tech from base image
                    lower = stripped.lower()
                    if "python" in lower: result["technologies"].append("Python")
                    if "node" in lower: result["technologies"].append("Node.js")
                    if "golang" in lower or "go" in lower: result["technologies"].append("Go")
                    if "java" in lower or "openjdk" in lower: result["technologies"].append("Java")
                    if "nginx" in lower: result["technologies"].append("Nginx")
                    break
            # Detect exposed ports
            for line in content.split("\n"):
                if line.strip().upper().startswith("EXPOSE "):
                    ports = line.strip().split()[1:]
                    result["summary"] += f", ports: {', '.join(ports)}"
                    break
        elif "docker-compose" in path:
            result["technologies"].extend(["Docker", "Docker Compose"])
            service_count = content.count("image:") + content.count("build:")
            # Try to extract service names
            services = re.findall(r'^\s{2}(\w[\w-]*):\s*$', content, re.MULTILINE)
            result["summary"] = f"Docker Compose: {service_count} services"
            if services:
                result["summary"] += f" ({', '.join(services[:6])})"
        elif "terraform" in path.lower() or path.endswith(".tf"):
            result["technologies"].append("Terraform")
            # Detect cloud provider
            if "aws" in content.lower(): result["technologies"].append("AWS")
            if "azurerm" in content.lower(): result["technologies"].append("Azure")
            if "google" in content.lower(): result["technologies"].append("GCP")
            result["summary"] = "Terraform IaC"
        elif "serverless" in path.lower():
            result["technologies"].extend(["Serverless Framework", "AWS Lambda"])
            result["summary"] = "Serverless deployment"
        elif "fly.toml" in path:
            result["technologies"].append("Fly.io")
            result["summary"] = "Fly.io deployment"

    elif category == "ci_cd":
        if ".github" in path:
            result["technologies"].append("GitHub Actions")
            result["summary"] = f"CI/CD: GitHub Actions ({path.rsplit('/', 1)[-1]})"
        elif ".gitlab" in path:
            result["technologies"].append("GitLab CI")
            result["summary"] = "CI/CD: GitLab CI"
        elif "Jenkins" in path:
            result["technologies"].append("Jenkins")
            result["summary"] = "CI/CD: Jenkins"

    elif category == "api_spec":
        result["technologies"].extend(["REST API", "OpenAPI"])
        # Try to extract API title
        title_match = re.search(r'title:\s*["\']?([^"\'\\n]+)', content)
        result["summary"] = f"OpenAPI: {title_match.group(1).strip() if title_match else 'API specification'}"

    elif category == "config":
        if ".env" in path:
            # Extract var names (not values!) for architecture hints
            vars_found = re.findall(r'^([A-Z][A-Z0-9_]+)=', content, re.MULTILINE)
            db_vars = [v for v in vars_found if any(kw in v for kw in ("DB", "DATABASE", "POSTGRES", "MYSQL", "REDIS", "MONGO"))]
            auth_vars = [v for v in vars_found if any(kw in v for kw in ("JWT", "AUTH", "SECRET", "TOKEN", "API_KEY", "OAUTH"))]
            result["summary"] = f"Env config: {len(vars_found)} vars"
            if db_vars: result["summary"] += f", DB: {', '.join(db_vars[:3])}"
            if auth_vars: result["summary"] += f", Auth: {', '.join(auth_vars[:3])}"

    return result if (result["technologies"] or result["summary"]) else None


def _build_system_description(
    repo_name: str,
    findings: list[dict[str, Any]],
    tech_stack: set[str],
    src_dirs: set,
) -> str:
    """Build a human-readable system description from analysis findings."""
    parts = [f"## Repository: {repo_name}\n"]

    if tech_stack:
        parts.append(f"**Tech Stack**: {', '.join(sorted(tech_stack))}\n")

    for category_name, display in [
        ("readme", "📖 About"),
        ("deployment", "🐳 Deployment"),
        ("ci_cd", "⚙️ CI/CD Pipeline"),
        ("package_manifest", "📦 Dependencies"),
        ("api_spec", "🔌 API Specifications"),
        ("config", "⚙️ Configuration"),
        ("security", "🔒 Security"),
    ]:
        cat_findings = [f for f in findings if f["category"] == category_name]
        if cat_findings:
            parts.append(f"\n### {display}")
            for f in cat_findings:
                summary = f["summary"]
                if category_name == "readme":
                    summary = summary[:300] + ("..." if len(summary) > 300 else "")
                parts.append(f"- **{f['file']}**: {summary}")

    if src_dirs:
        parts.append("\n### 📁 Source Structure")
        for d in sorted(src_dirs):
            parts.append(f"- `{d}/`")

    return "\n".join(parts)
