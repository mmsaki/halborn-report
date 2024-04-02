import json
from Issue import Issue

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
  