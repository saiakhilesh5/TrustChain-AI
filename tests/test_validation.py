import subprocess

from trustchain.validation.harness import BUMP_RE, find_bump_commits


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def test_bump_regex():
    match = BUMP_RE.match("chore(deps): bump qs from 6.16.2 to 6.17.0 (#28406)")
    assert match["name"] == "qs"
    assert match["from"] == "6.16.2"
    assert match["to"] == "6.17.0"
    match = BUMP_RE.match("chore(deps-dev): bump @babel/eslint-parser (#28511)")
    assert match is None
    match = BUMP_RE.match("chore(deps): bump @graphql-tools/utils from 12.0.3 to 12.0.4 (#28525)")
    assert match["name"] == "@graphql-tools/utils"


def test_find_bump_commits(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-b", "main")
    _git(repo, "config", "user.email", "t@example.com")
    _git(repo, "config", "user.name", "T")
    (repo / "yarn.lock").write_text("# yarn v1\n", encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "init")
    for message in [
        "chore(deps): bump qs from 6.16.2 to 6.17.0 (#28406)",
        "feat: something unrelated",
        "chore(deps-dev): bump prettier",
    ]:
        (repo / "yarn.lock").write_text(f"# {message}\n", encoding="utf-8")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-m", message)

    commits = find_bump_commits(repo, limit=5)
    assert len(commits) == 1
    assert commits[0]["name"] == "qs"
    assert commits[0]["from_version"] == "6.16.2"
    assert commits[0]["to_version"] == "6.17.0"
    assert len(commits[0]["sha"]) >= 7 and all(c in "0123456789abcdef" for c in commits[0]["sha"])
