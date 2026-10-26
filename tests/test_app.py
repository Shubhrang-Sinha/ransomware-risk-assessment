from pathlib import Path
from streamlit.testing.v1 import AppTest

APP = str(Path(__file__).parent.parent / "app.py")


def test_dashboard_runs_with_demo_data():
    at = AppTest.from_file(APP, default_timeout=90).run()
    assert not at.exception
    assert len(at.tabs) == 5


def test_dashboard_runs_in_questionnaire_mode():
    at = AppTest.from_file(APP, default_timeout=90).run()
    at.sidebar.radio[0].set_value("Answer the questionnaire").run()
    assert not at.exception
