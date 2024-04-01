import pytest
import json
from DependabotData import DependabotData


# open dependabot results.json and store results in `data` variable

@pytest.fixture
def data():
  path = './mediums.json'
  with open(path, 'r') as file:
    data = json.load(file)

  return data

class TestDependabotData:
  def test_one(self, data):
    self.data = DependabotData(data)
    assert all(issue for issue in self.data)

  def test_two(self, data):
    pass

  
# res = DependabotData(data)

# issue = res[9]
# print(f"number: {issue.number}")
# print(f"state: {issue.state}")
# print(f"ecosystem: {issue.ecosystem}")
# print(f"package: {issue.package}")
# print(f"name: {issue.name}")
# print(f"path: {issue.path}")
# print(f"scope: {issue.scope}")
# # print(f"advisory: {issue.advisory}")
# print(f"ghsa_id: {issue.ghsa_id}")
# print(f"cve_id: {issue.cve_id}")
# print(f"summary: {issue.summary}")
# # print(f"description: {issue.description}")
# print(f"severity: {issue.severity}")
# print(f"identifiers: {issue.all_ids}")
# # print(f"references: {issue.references}")
# print(f"published_at: {issue.published_at}")
# print(f"updated_at: {issue.updated_at}")
# print(f"withdrawn_at: {issue.withdrawn_at}")
# print(f"vulnerabilities: {issue.vulnerabilities}")
# print(f"cvss: {issue.cvss}")
# print(f"score: {issue.score}")
# print(f"cwes: {issue.all_cwes}")
# print(f"vulnerability: {issue.vulnerability}")
# print(f"vulnerabile_package: {issue.vulnerability}")
# print(f"vulnerability_serverity: {issue.vulnerability_serverity}")
# print(f"vulnerability_range: {issue.vulnerability_range}")
# print(f"vulnerability_patch: {issue.vulnerability_patch}")
# print(f"url: {issue.url}")
# print(f"html_url: {issue.html_url}")
# print(f"created_at: {issue.created_at}")
# print(f"updated_at: {issue.updated_at}")
# print(f"dismissed_at: {issue.dismissed_at}")
# print(f"dismissed_by: {issue.dismissed_by}")
# print(f"dismissed_reason: {issue.dismissed_reason}")