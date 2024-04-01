import pytest

class TestReport:
  def test_has_title(self, all_reports):
    self.data = all_reports
    assert all([report.title for report in self.data])

  def test_has_desc(self, all_reports):
    self.data = all_reports
    assert all(report.desc for report in self.data)