from src.tp1.utils.capture import Capture
from src.tp1.utils.report import Report
from reportlab.platypus import Table

def test_when_generate_table():
    # When
    capture = Capture()
    report = Report(capture, "report_test.pdf", capture.summary)
    table = report.generate_table()

    # Then
    assert type(table) == Table
