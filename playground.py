import json
from Dependabot import DependabotData
from Report import Report

path = './mediums.json'
with open(path, 'r') as file:
  data = json.load(file)


issues = DependabotData(data)
res = Report(issues)

print(res[0].title)
print(res[1].desc)
# print(res[0].description)
# for issue in res:
#   print(type(issue))
#   print(issue.vulnerability_patch)
#   break

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
# # print(f"references: {issue.references}")
# print(f"published_at: {issue.published_at}")
# print(f"updated_at: {issue.updated_at}")
# print(f"withdrawn_at: {issue.withdrawn_at}")
# print(f"vulnerabilities: {issue.vulnerabilities}")
# print(f"cvss: {issue.cvss}")
# print(f"score: {issue.score}")
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