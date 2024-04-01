
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
    self.title = self.type + "-" + str(self.number) + " " + self.issue.summary
    self.get_desc()

  def get_desc(self):
    if self.issue.is_markdown:
      pattern = '(?<=# Impact\n\n)((\\s*)(.+)(\\s*))+?(?=)'
      grep = re.search(pattern, self.issue.description)
      try:
        start = grep.start()
        end = grep.end()
        self.desc = self.issue.description[start:end].rstrip()
        self.has_impact = True
      except:
        # is markdown but no impact title
        self.has_impact = False
        self.desc = self.issue.description  
    else:
      self.has_impact = False
      self.desc = self.issue.description

