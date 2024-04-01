import pytest
import json
from DependabotData import DependabotData

# open dependabot results.json and store results in `data` variable
@pytest.fixture
def test_data():
  path = './results.json'
  with open(path, 'r') as file:
    data = json.load(file)

  yield DependabotData(data)