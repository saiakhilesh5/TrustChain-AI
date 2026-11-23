from trustchain import __version__
from trustchain.cli import main


def test_version_flag(capsys):
    try:
        main(["--version"])
    except SystemExit:
        pass
    assert __version__ in capsys.readouterr().out


def test_no_command_shows_help(capsys):
    assert main([]) == 1
    assert "usage" in capsys.readouterr().out.lower()


def test_scan_command_runs(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")
    assert main(["scan", "--target", str(tmp_path), "--output", str(tmp_path / "out")]) == 0
    assert (tmp_path / "out" / "inventory.json").exists()
