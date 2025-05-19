from src.tp1.utils.capture import Capture


def test_when_get_summary_then_return_summary():
    # Given
    capture = Capture()
    string = capture.summary

    # When
    result = capture.get_summary()

    # Then
    assert result == string

