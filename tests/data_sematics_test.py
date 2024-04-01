import pytest

class TestReport:
  def test_has_title(self, report_data):
    self.data = report_data
    assert all([report.title for report in self.data])

  def test_has_desc(self, report_data):
    self.data = report_data
    assert all(report.desc for report in self.data)

  # def test_