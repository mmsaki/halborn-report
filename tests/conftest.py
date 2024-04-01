import pytest
import json
from DependabotData import DependabotData
from Report import Report

# open dependabot results.json and store results in `data` variable
@pytest.fixture
def test_data():
  path = './results.json'
  with open(path, 'r') as file:
    data = json.load(file)

  return DependabotData(data)

@pytest.fixture
def report_data(test_data):
  return Report(test_data)
  