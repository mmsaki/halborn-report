import json
from pygments import highlight, lexers, formatters

class DependabotData:
  def __init__(self, data):
    self.data = data
    self._index = 0

  def __len__(self):
    return len(self.data)
  
  def __iter__(self):
    return self
  
  def __next__(self):
    if self._index < len(self.data):
      item = self.data[self._index]
      self._index += 1
      return item
    else:
      raise StopIteration
  
  def __getitem__(self, index):
    return Issue(self.data[index])

  def __str__(self):
    return highlight(json.dumps(self.data, indent=2), lexers.JsonLexer(), formatters.TerminalFormatter())
  

class Issue:
  def __init__(self, issue):
    self.issue                    = issue
    self.number                   = self.issue["number"]
    self.state                    = self.issue["state"]
    self.dependency               = self.issue["dependency"]
    self.package                  = self.dependency["package"]
    self.ecosystem                = self.package["ecosystem"]
    self.name                     = self.package["name"]
    self.path                     = self.dependency["manifest_path"]
    self.scope                    = self.dependency["scope"]
    self.advisory                 = self.issue["security_advisory"]
    self.ghsa_id                  = self.advisory["ghsa_id"]
    self.cve_id                   = self.advisory["cve_id"]
    self.summary                  = self.advisory["summary"]
    self.description              = self.advisory["description"]
    self.severity                 = self.advisory["severity"]
    self.identifiers              = self.advisory["identifiers"]
    self.all_ids()                # self.all_ids created here
    self.references               = [url["url"] for url in self.advisory["references"]]
    self.published_at             = self.advisory["published_at"]
    self.updated_at               = self.advisory["updated_at"]
    self.withdrawn_at             = self.advisory["withdrawn_at"]
    self.vulnerabilities          = self.advisory["vulnerabilities"]
    self.all_vuls()               # self.all_vuls created here
    self.cvss                     = self.advisory["cvss"]["vector_string"]
    self.score                    = self.advisory["cvss"]["score"]
    self.cwes                     = self.advisory["cwes"] 
    self.all_cwes()               # self.all_cwes created here
    self.vulnerability            = self.issue["security_vulnerability"]
    self.vulnerability_package    = self.vulnerability["package"]["name"]
    self.vulnerability_serverity  = self.vulnerability["severity"]
    self.vulnerability_range      = self.vulnerability["vulnerable_version_range"]
    self.vulnerability_patch      = self.vulnerability["first_patched_version"]["identifier"]
    self.url                      = self.issue["url"]
    self.html_url                 = self.issue["html_url"]
    self.created_at               = self.issue["created_at"]
    self.updated_at               = self.issue["updated_at"]
    self.dismissed_at             = self.issue["dismissed_at"]
    self.dismissed_by             = self.issue["dismissed_by"]
    self.dismissed_reason         = self.issue["dismissed_reason"]


  def __str__(self):
    return highlight(json.dumps(self.issue, indent=2), lexers.PythonLexer(), formatters.TerminalFormatter())

  def all_vuls(self):
    items = []
    for vul in self.vulnerabilities:
      items.append(f"name: {vul['package']['name']}, severity: {vul['severity']}, vulnerable_version: {vul['vulnerable_version_range']}, patch_version: {vul['first_patched_version']['identifier']}")
    self.all_vuls = items
  
  def all_cwes(self):
    items = []
    for cwe in self.cwes:
      items.append(f"{cwe['name']} - {cwe['cwe_id']}")
    self.all_cwes = items
  
  def all_ids(self):
    items = []
    for id in self.identifiers:
      if id["type"].upper() == "GHSA":
        items.append("{url-ghsa}" + f"{id['value']}" + f"[{id['value']}]")
      if id["type"].upper() == "CVE":
        items.append("{url-nist}" + f"{id['value']}" + f"[{id['value']}]")
    self.all_ids = items