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


def test_unknown_command_is_graceful(capsys):
    assert main(["scan", "--target", "x", "--output", "y"]) == 2
