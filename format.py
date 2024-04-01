import json
from generate_report import generate_lows, generate_mediums, generate_highs, generate_criticals, get_classified_vunerabilities

# open dependabot results.json and store results in `data` variable
path = './mediums.json'
with open(path, 'r') as file:
  data = json.load(file)


# lows = generate_lows(data)
# lows_path = "./report/findings-low.adoc"
# with open(lows_path, 'w') as file:
#   file.write("".join(lows))

#   print("done", len(lows))

# print(highlight(lows, lexers.JsonLexer(), formatters.TerminalFormatter()))


med = generate_mediums(data)
med_path = "./report/findings-med.adoc"
with open(med_path, 'w') as file:
  file.write("".join(med))

  print("done", len(med), len(data))

# highs = generate_highs(data)
# highs_path = "./report/findings-high.adoc"
# with open(highs_path, 'w') as file:
#   file.write("".join(highs))

#   print("done", len(highs))

# criticals = generate_criticals(data)
# critical_path = "./report/findings-critical.adoc"
# with open(critical_path, 'w') as file:
#   file.write("".join(criticals))

#   print("done", len(criticals))


# def save_meds():
#   (_, _, med, _) = get_classified_vunerabilities(data)
#   med_path = "./mediums.json"
#   with open(med_path, 'w') as file:
#     file.write(json.dumps(med))

#   print("done", len(med))

# save_meds()