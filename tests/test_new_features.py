"""Tests for YAML Model Parser, Diff Engine, Repo Analyzer, and URL Detection."""

import pytest

from agentictm.parsers.yaml_model import (
    detect_structured_input,
    parse_structured_input,
)
from agentictm.agents.diff_engine import diff_threat_models
from agentictm.agents.repo_analyzer import (
    detect_repo_urls,
    RepoInfo,
    _categorize_file,
    enrich_input_with_repos,
    RepoAnalysisResult,
)


# ---------------------------------------------------------------------------
# Repo URL Detection Tests
# ---------------------------------------------------------------------------

class TestDetectRepoUrls:
    def test_detects_github_url(self):
        repos = detect_repo_urls("Check out https://github.com/org/myrepo for details")
        assert len(repos) == 1
        assert repos[0].platform == "github"
        assert repos[0].owner == "org"
        assert repos[0].repo == "myrepo"

    def test_detects_gitlab_url(self):
        repos = detect_repo_urls("See https://gitlab.com/team/project for code")
        assert len(repos) == 1
        assert repos[0].platform == "gitlab"

    def test_detects_multiple_repos(self):
        text = "Frontend: https://github.com/org/frontend and backend: https://github.com/org/backend"
        repos = detect_repo_urls(text)
        assert len(repos) == 2
        names = {r.repo for r in repos}
        assert "frontend" in names
        assert "backend" in names

    def test_deduplicates_repos(self):
        text = "https://github.com/org/repo and again https://github.com/org/repo"
        repos = detect_repo_urls(text)
        assert len(repos) == 1

    def test_detects_branch_url(self):
        repos = detect_repo_urls("https://github.com/org/repo/tree/develop")
        assert len(repos) == 1
        assert repos[0].branch == "develop"

    def test_no_repos_in_plain_text(self):
        repos = detect_repo_urls("This is a plain text description of my system")
        assert len(repos) == 0

    def test_empty_input(self):
        assert detect_repo_urls("") == []

    def test_handles_git_suffix(self):
        repos = detect_repo_urls("Clone https://github.com/org/repo.git")
        assert len(repos) == 1
        assert repos[0].repo == "repo"

    def test_mixed_platforms(self):
        text = "https://github.com/org/gh and https://gitlab.com/team/gl"
        repos = detect_repo_urls(text)
        assert len(repos) == 2
        platforms = {r.platform for r in repos}
        assert "github" in platforms
        assert "gitlab" in platforms


class TestCategorizeFile:
    def test_dockerfile(self):
        assert _categorize_file("Dockerfile") == "deployment"

    def test_ci_workflow(self):
        assert _categorize_file(".github/workflows/ci.yml") == "ci_cd"

    def test_package_json(self):
        assert _categorize_file("package.json") == "package_manifest"

    def test_openapi_spec(self):
        assert _categorize_file("openapi.yaml") == "api_spec"

    def test_readme(self):
        assert _categorize_file("README.md") == "readme"

    def test_irrelevant_file(self):
        assert _categorize_file("src/main.py") is None


class TestEnrichInput:
    def test_enriches_with_description(self):
        result = RepoAnalysisResult(
            repo=RepoInfo(platform="github", owner="org", repo="test", url=""),
            system_description="## Repository: org/test\n**Tech Stack**: Python",
        )
        enriched = enrich_input_with_repos("My system description", [result])
        assert "My system description" in enriched
        assert "Repository Analysis" in enriched
        assert "org/test" in enriched

    def test_enriches_with_error(self):
        result = RepoAnalysisResult(
            repo=RepoInfo(platform="github", owner="org", repo="private", url=""),
            error="Authentication failed",
        )
        enriched = enrich_input_with_repos("My system", [result])
        assert "Authentication failed" in enriched

    def test_no_repos_returns_original(self):
        assert enrich_input_with_repos("original text", []) == "original text"


# ---------------------------------------------------------------------------
# YAML/JSON Parser Tests
# ---------------------------------------------------------------------------

class TestDetectStructuredInput:
    def test_detects_json(self):
        assert detect_structured_input('{"components": []}') == "json"

    def test_detects_yaml(self):
        yaml_input = """
system_name: My App
components:
  - name: API
    type: process
data_flows:
  - source: Client
    destination: API
"""
        assert detect_structured_input(yaml_input) == "yaml"

    def test_returns_none_for_text(self):
        assert detect_structured_input("This is a regular text description") is None

    def test_returns_none_for_empty(self):
        assert detect_structured_input("") is None


class TestParseStructuredInput:
    def test_parses_json(self):
        json_input = """{
            "system_name": "Test System",
            "components": [
                {"name": "API", "type": "process", "technology": "FastAPI"},
                {"name": "DB", "type": "datastore", "technology": "PostgreSQL"}
            ],
            "data_flows": [
                {"source": "API", "destination": "DB", "protocol": "TCP"}
            ]
        }"""
        result = parse_structured_input(json_input)
        assert result is not None
        assert result["system_name"] == "Test System"
        assert len(result["components"]) == 2
        assert len(result["data_flows"]) == 1

    def test_parses_yaml(self):
        yaml_input = """
system_name: E-Commerce
components:
  - name: Frontend
    type: process
    technology: React
  - name: Backend
    type: process
    technology: Node.js
data_flows:
  - source: Frontend
    destination: Backend
    protocol: HTTPS
trust_boundaries:
  - name: Internet to DMZ
    components_inside: [Backend]
    components_outside: [Frontend]
"""
        result = parse_structured_input(yaml_input)
        assert result is not None
        assert result["system_name"] == "E-Commerce"
        assert len(result["components"]) == 2
        assert len(result["trust_boundaries"]) == 1

    def test_returns_none_for_text(self):
        result = parse_structured_input("Just a plain text description")
        assert result is None

    def test_handles_alternate_keys(self):
        json_input = """{
            "name": "Alt System",
            "services": [{"name": "svc1"}],
            "flows": [{"from": "A", "to": "B"}],
            "boundaries": [{"name": "edge"}]
        }"""
        result = parse_structured_input(json_input)
        assert result is not None
        assert result["system_name"] == "Alt System"
        assert len(result["components"]) == 1
        assert result["data_flows"][0]["source"] == "A"


# ---------------------------------------------------------------------------
# Diff Engine Tests
# ---------------------------------------------------------------------------

class TestDiffEngine:
    def _make_threat(self, id, desc="desc", priority="High", dread_total=25):
        return {
            "id": id,
            "description": desc,
            "priority": priority,
            "dread_total": dread_total,
            "stride_category": "S",
        }

    def test_identical_models(self):
        threats = [self._make_threat("T1"), self._make_threat("T2")]
        diff = diff_threat_models(threats, threats)
        assert diff["summary"]["added_count"] == 0
        assert diff["summary"]["removed_count"] == 0
        assert diff["summary"]["unchanged_count"] == 2

    def test_added_threats(self):
        old = [self._make_threat("T1")]
        new = [self._make_threat("T1"), self._make_threat("T2")]
        diff = diff_threat_models(old, new)
        assert diff["summary"]["added_count"] == 1
        assert len(diff["added"]) == 1
        assert diff["added"][0]["id"] == "T2"

    def test_removed_threats(self):
        old = [self._make_threat("T1"), self._make_threat("T2")]
        new = [self._make_threat("T1")]
        diff = diff_threat_models(old, new)
        assert diff["summary"]["removed_count"] == 1
        assert len(diff["removed"]) == 1

    def test_modified_threat(self):
        old = [self._make_threat("T1", priority="Medium")]
        new = [self._make_threat("T1", priority="Critical")]
        diff = diff_threat_models(old, new)
        assert diff["summary"]["modified_count"] == 1
        assert any(c["field"] == "priority" for c in diff["modified"][0]["changes"])

    def test_risk_trend(self):
        old = [self._make_threat("T1", dread_total=10)]
        new = [self._make_threat("T1", dread_total=40)]
        diff = diff_threat_models(old, new)
        assert diff["summary"]["risk_trend"] == "increased"

    def test_empty_models(self):
        diff = diff_threat_models([], [])
        assert diff["summary"]["old_count"] == 0
        assert diff["summary"]["new_count"] == 0

    def test_similarity_matching(self):
        old = [self._make_threat("old-1", desc="SQL injection vulnerability in login endpoint")]
        new = [self._make_threat("new-1", desc="SQL injection vulnerability in login endpoint API")]
        diff = diff_threat_models(old, new)
        # Should match by description similarity
        assert diff["summary"]["modified_count"] == 1
        assert diff["summary"]["added_count"] == 0
        assert diff["summary"]["removed_count"] == 0
