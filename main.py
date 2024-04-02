import json
from utils import get_classified_vunerabilities

from Dependabot import DependabotData
from Report import Report

# open dependabot results.json and store results in `data` variable
path = './results.json'
with open(path, 'r') as file:
  data = json.load(file)


def write_issues():
  (criticals, highs, mediums, lows) = get_classified_vunerabilities(data)
  CRITICALS_PATH = "./report/findings-critical.adoc"
  HIGHS_PATH = "./report/findings-high.adoc"
  MEDIUMS_PATH = "./report/findings-med.adoc"
  LOWS_PATH = "./report/findings-low.adoc"

  bot_criticals = DependabotData(data=criticals)
  bot_highs = DependabotData(data=highs)
  bot_mediums = DependabotData(data=mediums)
  bot_lows = DependabotData(data=lows)

  report_criticals= Report(issues=bot_criticals)
  report_highs = Report(issues=bot_highs)
  report_mediums = Report(issues=bot_mediums)
  report_lows = Report(issues=bot_lows)
  
  with open(CRITICALS_PATH, 'w') as file:
    file.write("".join([str(issue) for issue in report_criticals]))
    print("criticals", len(criticals))
  
  with open(HIGHS_PATH, 'w') as file:
    file.write("".join([str(issue) for issue in report_highs]))
    print("highs", len(highs))

  with open(MEDIUMS_PATH, 'w') as file:
    file.write("".join([str(issue) for issue in report_mediums]))
    print("highs", len(mediums))

  with open(LOWS_PATH, 'w') as file:
    file.write("".join([str(issue) for issue in report_lows]))
    print("highs", len(lows))

write_issues()



# save_issues()