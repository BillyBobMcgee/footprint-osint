import io

from footprint import output
from footprint.models import SiteHit


def _cp1252_stdout(monkeypatch):
    """A stand-in for a default Windows console, which cannot encode much."""
    stream = io.TextIOWrapper(io.BytesIO(), encoding="cp1252", newline="")
    monkeypatch.setattr("sys.stdout", stream)
    return stream


def test_a_cyrillic_site_name_does_not_kill_the_scan(monkeypatch):
    """A whole username sweep used to die at the point it printed the table."""
    stream = _cp1252_stdout(monkeypatch)
    output.tolerate_narrow_encoding()

    output.render_username([SiteHit(site="ВКонтакте", url="https://vk.com/x",
                                    exists=True)])

    stream.flush()
    assert b"vk.com/x" in stream.buffer.getvalue()


def test_reconfiguring_a_stream_that_cannot_be_reconfigured_is_harmless():
    """pytest and the GUI hand us stand-in streams; neither must raise."""
    monkeypatched = io.StringIO()
    import sys
    original = sys.stdout
    sys.stdout = monkeypatched
    try:
        output.tolerate_narrow_encoding()
    finally:
        sys.stdout = original
