import pytest
import json
from Dependabot import DependabotData
from Report import Report

# open dependabot results.json and store results in `data` variable
@pytest.fixture
def all_data():
  path = './results.json'
  with open(path, 'r') as file:
    data = json.load(file)
  return DependabotData(data)

@pytest.fixture
def all_reports(all_data):
  return Report(all_data)