
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
  def __init__(self, issue, severity, number):
    self.issue = issue
    self.type = severity.upper()[0]
    self.number = number
    self.title = self.type + "-" + str(self.number) + " " + issue.summary
    self.desc = self.conver_to_asciidoc(issue.description)

  def conver_to_asciidoc(self, string):
    """
    Converts .md syntax to .asccidoc syntax
      in:  "### My Links\n\n* [Blog](https://msaki.io)\n* [Github](https://github.com/mmsaki)\n* Thank you"
      out: "### My Links\n\n* https://msaki.io[Blog]\n* https://github.com/mmsaki[Github]\n* Thank you"
    """
    pattern = '(\[)(.+?)(\])(\()(.+?)(\))'
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
    
  def convert_md_link(self, string):
    """
    Converts a markdown links to asciidoc links
      in:  [My Website](https://msaki.io)
      out: https://msaki.io[My Website]
    """
    pattern = '(\[)(.+?)(\])(\()(.+?)(\))'
    grep = re.compile(pattern)
    found = grep.findall(string)
    return found[0][4] + "".join(found[0][0:3])