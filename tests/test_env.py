from trustchain.env import load_env


def test_load_env_populates_missing_keys(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# comment\nGEMINI_API_KEY_1=key-one\nGEMINI_API_KEY_2=\"quoted\"\nBROKEN LINE\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("GEMINI_API_KEY_1", raising=False)
    import os

    monkeypatch.delenv("GEMINI_API_KEY_2", raising=False)
    load_env(env_file)
    assert os.environ["GEMINI_API_KEY_1"] == "key-one"
    assert os.environ["GEMINI_API_KEY_2"] == "quoted"


def test_load_env_does_not_override_existing(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("GEMINI_API_KEY_1=from-file\n", encoding="utf-8")
    monkeypatch.setenv("GEMINI_API_KEY_1", "from-env")
    load_env(env_file)
    import os

    assert os.environ["GEMINI_API_KEY_1"] == "from-env"


def test_load_env_missing_file(tmp_path):
    assert load_env(tmp_path / "nope.env") == tmp_path / "nope.env"
