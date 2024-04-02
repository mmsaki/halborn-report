
from ReportItem import ReportItem

class Report():
  def __init__(self, issues):
    self.issues = [ReportItem(issue, issue.severity, number + 1) for number, issue in enumerate(issues)]
    self._index = 0

  def __str__(self):
    return f"{''.join([str(item) for item in self.issues])}"

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
