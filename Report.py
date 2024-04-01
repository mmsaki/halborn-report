
import re
import json
from DependabotData import DependabotData, Issue

class Report():
  def __init__(self, issues):
    self.issues = [ReportItem(issue, issue.severity, number) for number, issue in enumerate(issues)]
    self._index = 0

  def __str__(self):
    return f"Report(length={len(self.issues)})"

  def __getitem__(self, index):
    return self.issues[index]

  def __iter__(self):
    return self

  def __next__(self):
    if self._index < len(self.issues):
      item = self.issues[self._index]
      self._index += 1
      return item
    else:
      raise StopIteration

class ReportItem():
  # Constants
  URL_CWE  = "{url-cwe}"
  URL_NIST = "{url-nist}"
  URL_GHSA = "{url-ghsa}"
  URL_REPO = "{url-repo}"
  URL_BLOB = "{url-blob}"
  FILE_DIR = "{ctf-dir}"

  def __init__(self, issue: Issue, severity: str, number: int):
    self.issue = issue
    self.type = severity.upper()[0]
    self.number = number
    self.title = self.type + "-" + str(self.number) + " " + issue.summary
    self.desc = self.conver_to_asciidoc(issue.description)
    self.cwes = self.get_cwes(issue.cwes)
    self.tags = f"Tags: `{issue.scope}`{f', Weakness: {self.cwes}' if self.cwes else ''}{f', CVE ID: {self.URL_NIST}{issue.cve_id}[{issue.cve_id}]' if issue.cve_id else ''}{f', GHSA ID: {self.URL_GHSA}{issue.ghsa_id}[{issue.ghsa_id}]' if issue.ghsa_id else ''}"

  def __str__(self) -> str:
    return f"""## tag::{self.number}[]
== {self.title}
{self.tags}

{self.desc}

## end::{self.number}[]
"""

  def conver_to_asciidoc(self, string) -> str:
    """
    Converts markdown syntax to asccidoc syntax

    in:  \n* [Blog](https://msaki.io)\n* [Github](https://github.com/mmsaki)\n* Thank you\n
    out: \n* https://msaki.io[Blog]\n* https://github.com/mmsaki[Github]\n* Thank you
    """
    pattern = r'(\[)(.+?)(\])(\()(.+?)(\))'
    grep = re.compile(pattern)
    try:
      found = grep.finditer(string)
      count = 0
      for item in found:
        start = item.start()
        end = item.end()
        group = item.group(0)
        string = string[0:start - count] + self.convert_md_link(group) + string[end - count:]
        count += 2
    except:
      print("Reached Except")
    string = string.replace("####", "===")
    string = string.replace("###", "===")
    string = string.replace("##", "===")
    string = string.replace("#", "===")
    return string
    
  def convert_md_link(self, string) -> str:
    """
    Converts a markdown links to asciidoc links

    in:  [My Website](https://msaki.io)
    out: https://msaki.io[My Website]
    """
    pattern = r'(\[)(.+?)(\])(\()(.+?)(\))'
    grep = re.compile(pattern)
    found = grep.findall(string)
    return found[0][4] + "".join(found[0][0:3])
  
  def get_cwes(self, cwes):
    """Converts all cwes to asciidoc format"""
    ids = [i['cwe_id'] for i in cwes]
    links = [self.URL_CWE + f'{cwes.split("-")[1]}.html[{cwes}]' for cwes in ids]
    return ", ".join(links)