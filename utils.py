import re
import json

def get_classified_vunerabilities(raw_data):
  """Takes raw json data from dependabot and classifies them according to serverity"""
  
  medium = [] 
  high = []
  low = []
  critical = []
  for vul in raw_data:
    if vul["security_advisory"]["severity"].lower() == "medium":
      medium.append(vul)
    elif vul["security_advisory"]["severity"].lower() == "low":
      low.append(vul)
    elif vul["security_advisory"]["severity"].lower() == "high":
      high.append(vul)
    elif vul["security_advisory"]["severity"].lower() == "critical":
      critical.append(vul)
    else:
      low.append(vul)
  return (critical, high, medium, low)

def save_issues(data: list):
  """Creates separate json files accodrding to severity"""

  (criticals, highs, mediums, lows) = get_classified_vunerabilities(data)
  MEDIUMS_PATH = "./mediums.json"
  LOWS_PATH = "./lows.json"
  HIGHS_PATH = "./highs.json"
  CRITICALS_PATH = "./criticals.json"

  with open(MEDIUMS_PATH, 'w') as file:
    file.write(json.dumps(mediums))

  with open(LOWS_PATH, 'w') as file:
    file.write(json.dumps(lows))

  with open(HIGHS_PATH, 'w') as file:
    file.write(json.dumps(highs))

  with open(CRITICALS_PATH, 'w') as file:
    file.write(json.dumps(criticals))

  print("done")

def find_line(dependency, filename):
  """Finds the line number where dependecy was used in filepath"""

  lookup = dependency
  with open(filename) as myFile:
    for num, line in enumerate(myFile, 1): # first line is not zero indexed
      if lookup in line:
        return num

def get_cvss(cvss):
  """
  Gets cvss3.1 level impact and assigns equivalent long string name 
  in  -> "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L"
  out -> ('Local', 'High', 'High', 'High', 'Required', 'Unchange', 'Low', 'Low', 'Low')
  """

  # initialize cvss variables
  AV, AC, PR, PR, UI, S, C, I, A = "","","","","","","","",""
  try:
    AV = cvss[re.search('/AV:', cvss).span()[1]]
    AC = cvss[re.search('/AC:', cvss).span()[1]]
    PR = cvss[re.search('/PR:', cvss).span()[1]]
    UI = cvss[re.search('/UI:', cvss).span()[1]]
    S  = cvss[re.search('/S:', cvss).span()[1]]
    C  = cvss[re.search('/C:', cvss).span()[1]]
    I  = cvss[re.search('/I:', cvss).span()[1]]
    A  = cvss[re.search('/A:', cvss).span()[1]]
  except:
    pass

  # Access vector
  AV_L = "local"
  AV_A = "adjacent"
  AV_N = "network" 
  AV_P = "physical"
  if AV == "L": AV = AV_L.title()
  elif AV == "A": AV = AV_A.title()
  elif AV == "N": AV = AV_N.title()
  elif AV == "P": AV = AV_P.title()
  
  # Access complexity
  AC_H = "high" 
  AC_L = "low" 
  if AC == "H": AC = AC_H.title()
  elif AC == "L": AC = AC_L.title()

	# Priviledges Required 
  PR_N = "none"
  PR_H = "high"
  PR_L = "low"
  if PR == "N": PR = PR_N.title()
  elif PR == "H": PR = PR_H.title()
  elif PR == "L": PR = PR_L.title()

  # User Interaction
  UI_N = "none" 
  UI_R = "required" 
  if UI == "N": UI = UI_N.title()
  elif UI == "R": UI = UI_R.title()

  # Scope
  S_U = "unchange"
  S_C = "changed"  
  if S == "U": S = S_U.title()
  elif S == "C": S = S_C.title()

	# Confidentiality
  C_N = "none"
  C_H = "high"
  C_L = "low"  
  if C == "N": C = C_N.title()
  elif C == "L": C = C_L.title()
  elif C == "H": C = C_H.title()

	# Integrity
  I_N = "none"
  I_L = "low"
  I_H = "high" 
  if I == "N": I = I_N.title()
  elif I == "L": I = I_L.title()
  elif I == "H": I = I_H.title()

  # Avaliability
  A_N = "none"
  A_L = "low"  
  A_H = "high" 
  if A == "N": A = A_N.title()
  elif A == "L": A = A_L.title()
  elif A == "H": A = A_H.title()

  return (AV, AC, PR, PR, UI, S, C, I, A)

