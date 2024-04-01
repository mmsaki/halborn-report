import json

class DependabotData:
  def __init__(self, data: list):
    self.data = [Issue(issue) for issue in data]
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
  
  def __getitem__(self, index: int):
    return self.data[index]

  def __str__(self):
    return json.dumps(self.data, indent=2)
  
  def __repr__(self):
    return f"DependabotData(length={len(self.data)})"

class Issue:
  def __init__(self, issue: dict):
    self.issue                   : dict = issue
    self.number                  : int  = self.issue["number"]
    self.state                   : str  = self.issue["state"]
    self.dependency              : dict = self.issue["dependency"]
    self.package                 : dict = self.dependency["package"]
    self.ecosystem               : str  = self.package["ecosystem"]
    self.name                    : str  = self.package["name"]
    self.path                    : str  = self.dependency["manifest_path"]
    self.scope                   : str  = self.dependency["scope"]
    self.advisory                : dict = self.issue["security_advisory"]
    self.ghsa_id                 : str  = self.advisory["ghsa_id"]
    self.cve_id                  : str  = self.advisory["cve_id"]
    self.summary                 : str  = self.advisory["summary"]
    self.description             : str  = self.advisory["description"]
    self.is_markdown             : bool = self.description.startswith("#") or  self.description.contains("##")
    self.severity                : str  = self.advisory["severity"]
    self.identifiers             : list = self.advisory["identifiers"]
    self.references              : list = [url["url"] for url in self.advisory["references"]]
    self.published_at            : str  = self.advisory["published_at"]
    self.updated_at              : str  = self.advisory["updated_at"]
    self.withdrawn_at            : str  = self.advisory["withdrawn_at"]
    self.vulnerabilities         : list = self.advisory["vulnerabilities"]
    self.cvss                    : str  = self.advisory["cvss"]["vector_string"]
    self.score                   : str  = self.advisory["cvss"]["score"]
    self.cwes                    : list = self.advisory["cwes"] 
    self.vulnerability           : dict = self.issue["security_vulnerability"]
    self.vulnerability_package   : str  = self.vulnerability["package"]["name"]
    self.vulnerability_serverity : str  = self.vulnerability["severity"]
    self.vulnerability_range     : str  = self.vulnerability["vulnerable_version_range"]
    self.vulnerability_patch     : dict = self.vulnerability["first_patched_version"]
    self.has_patch               : bool = bool(self.vulnerability["first_patched_version"])
    self.url                     : str  = self.issue["url"]
    self.html_url                : str  = self.issue["html_url"]
    self.created_at              : str  = self.issue["created_at"]
    self.updated_at              : str  = self.issue["updated_at"]
    self.dismissed_at            : str  = self.issue["dismissed_at"]
    self.dismissed_by            : str  = self.issue["dismissed_by"]
    self.dismissed_reason        : str  = self.issue["dismissed_reason"]

  def __str__(self):
    return json.dumps(self.issue, indent=2)
  
  def __repr__(self):
    return f"Issue(number={self.number}, severity={self.severitiy}, package={self.name})"