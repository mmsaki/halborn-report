from Issue import Issue
from utils import get_cvss
import re

class ReportItem():
  # Constants
  URL_CWE   = "{url-cwe}"
  URL_NIST  = "{url-nist}"
  URL_GHSA  = "{url-ghsa}"
  URL_REPO  = "{url-repo}"
  URL_BLOB  = "{url-blob}"
  FILE_DIR  = "{ctf-dir}"
  AUDIT_DIR = "./CTFs/"  

  def __init__(self, issue: Issue, severity: str, number: int):
    self.issue = issue
    self.type = severity.upper()[0]
    self.number = number
    self.title = self.type + "-" + str(self.number) + " " + issue.summary
    self.desc = self.conver_to_asciidoc(issue.description)
    self.cwes = self.get_cwes(issue.cwes)
    self.tags = f"Tags: `{issue.scope}`{f', Weakness: {self.cwes}' if self.cwes else ''}{f', CVE ID: {self.URL_NIST}{issue.cve_id}[{issue.cve_id}]' if issue.cve_id else ''}{f', GHSA ID: {self.URL_GHSA}{issue.ghsa_id}[{issue.ghsa_id}]' if issue.ghsa_id else ''}"
    self.package = issue.package['name']
    self.query = self.package if issue.ecosystem == 'go' else "name = " + f'"{self.package}"'
    self.line = self.find_line(self.query, self.AUDIT_DIR + issue.file_path)
    self.permalink = f".File {self.URL_REPO}{self.URL_BLOB}{issue.file_path}#L{self.line}"
    self.language = issue.ecosystem
    self.file_path = issue.file_path
    self.score = str(issue.score) + '/10'
    (self.AV, self.AC, self.PR, self.PR, self.UI, self.S, self.C, self.I, self.A) = get_cvss(issue.cvss)
    self.cvss = f"""
=== CVSS Score: {self.score}
.{self.issue.cvss}
[%header]
|===
2+| CVSS base metrics
| Attack vector | {self.AV}
| Attack complexity | {self.AC}
| Privileges required | {self.PR}
| User interaction | {self.UI}
| Scope | {self.S}
| Confidentiality | {self.C}
| Integrity | {self.I}
| Availability  | {self.A}
|==="""

  def __repr__(self) -> str:
    return f"""## tag::{self.number}[]
== {self.title}
{self.tags}

{self.permalink}
[source,{self.language}]
---- 
++++ <.>
include::{self.FILE_DIR}{self.file_path}[lines={self.line if self.issue.ecosystem == 'go' else f'{self.line-1}..{self.line + 3}'}]
++++
----
{self.cvss if self.issue.has_cvss else ''}

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
    string = string.replace("#### ", "=== ")
    string = string.replace("### ", "=== ")
    string = string.replace("## ", "=== ")
    string = string.replace("# ", "=== ")
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
  
  def find_line(self, dependecy: str, filename: str):
    with open(filename, 'r') as file:
      for num, line in enumerate(file, 1):
        if dependecy in line:
          return num