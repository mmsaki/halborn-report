import pytest
import json
from DependabotData import DependabotData


# open dependabot results.json and store results in `data` variable

@pytest.fixture
def test_data():
  path = './results.json'
  with open(path, 'r') as file:
    data = json.load(file)

  yield DependabotData(data)

class TestDependabotData:
  def test_all_issues_present(self, test_data):
    self.issues = test_data
    assert all(issue for issue in self.issues)
  
  def test_all_issues_with_values(self, test_data):
    self.issues = test_data
    assert all(
      all([
        issue.number,
        issue.state,
        issue.ecosystem,
        issue.package,
        issue.name,
        issue.path,
        issue.scope,
        issue.advisory,
        issue.ghsa_id,
        # issue.cve_id,                 (not all issues have)
        issue.summary,
        issue.description,
        issue.severity,
        issue.identifiers,
        issue.references,
        issue.published_at,
        issue.updated_at,
        # issue.withdrawn_at,           (not all issues have)
        issue.vulnerabilities,
        # issue.cvss,                   (not all issues have)
        # issue.score,                  (not all issues have)
        # issue.cwes,                   (not all issues have)
        issue.vulnerability,
        # issue.vulnerabile_package,    (not all issues have)
        issue.vulnerability_serverity,
        issue.vulnerability_range,
        # issue.vulnerability_patch,    (not all issues have)
        issue.url,
        issue.html_url,
        issue.created_at,
        issue.updated_at,
        # issue.dismissed_at,           (not all issues have)
        # issue.dismissed_by,           (not all issues have)
        # issue.dismissed_reason,       (not all issues have)
      ])
      for issue in self.issues
      )