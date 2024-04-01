import re

# converts cwe list to one template string
# in  -> [{'cwe_id': 'CWE-682', 'name': 'Incorrect Calculation'}, {'cwe_id': 'CWE-709', 'name': 'Incorrect Calculation'}]
# out -> '{url_cwe}682.html[CWE-682], {url_cwe}709.html[CWE-709]'
def get_cwes(cwes):
  ids = [i['cwe_id'] for i in cwes]
  links = ['{url-cwe}' + f'{cwes.split("-")[1]}.html[{cwes}]' for cwes in ids]
  return ", ".join(links)


# Finds the line number where dependecy was used in a Cargo.Lock file
def find_line(dependency, filename):
  lookup = dependency
  with open(filename) as myFile:
    for num, line in enumerate(myFile, 1):
      if lookup in line:
        return num

# gets the serverity of issue and assigns a symbol
def get_symbol(severity):
  sym = ""
  if severity.lower() == "medium":
    sym = "M-"
  elif severity.lower() == "critical":
    sym = "C-"
  elif severity.lower() == "low":
    sym = "L-"
  else:
    sym = ""
  return sym

# converts a markdown links to asciidoc links
# in  -> [My Website](https://msaki.io)
# out -> https://msaki.io[My Website]
def convert_md_link(string):
  pattern = '(\[)(.+?)(\])(\()(.+?)(\))'
  p = re.compile(pattern)
  v = p.findall(string)
  return v[0][4] + "".join(v[0][0:3])

# Converts .md syntax to .asccidoc syntax
# in  -> "### My Links\n\n* [Web](https://msaki.io)\n* [Github](https://github.com/mmsaki)\n* Thank you"
# out -> "### My Links\n\n* https://msaki.io[Web]\n* https://github.com/mmsaki[Github]\n* Thank you"
def convert_desc(desc):
  pattern = '(\[)(.+?)(\])(\()(.+?)(\))'
  p = re.compile(pattern)
  v = p.finditer(desc)
  count = 0
  for m in v:
    start = m.start()
    end = m.end()
    group = m.group(0)
    desc = desc[0:start - count] + convert_md_link(group) + desc[end - count:]
    count += 2
  desc = desc.replace("#### ", "=== ")
  desc = desc.replace("### ", "=== ")
  desc = desc.replace("## ", "=== ")
  desc = desc.replace("# ", "=== ")
  return desc

# get body of Impact description
def get_impact(string):
  pattern = '(?<==== Impact\n\n)((\s*)(.+)(\s*))+?(?====)'
  g = re.search(pattern, string)
  try:
    start = g.start()
    end = g.end()
  except:
    return ""
  return string[start:end].rstrip()

# get body of Patches description
def get_patches(string):
  pattern = '(?<==== Patches\n\n)((\s*)(.+)(\s*))+?(?====)'
  g = re.search(pattern, string)
  try:
    start = g.start()
    end = g.end()
  except:
    return ""
  return string[start:end].rstrip()

# get body of Workarounds description
def get_workarounds(string):
  pattern = '(?<==== Workarounds\n\n)((\s*)(.+)(\s*))+?(?====)'
  g = re.search(pattern, string)
  try:
    start = g.start()
    end = g.end()
  except:
    return ""
  return string[start:end].rstrip()

# get body of References description
def get_references(string):
  pattern = '(?<==== References\n\n)((\s*)(.+)(\s*))+?(?====)'
  g = re.search(pattern, string)
  try:
    start = g.start()
    end = g.end()
  except:
    return ""
  return string[start:end].rstrip()

# get body of For more information description
def get_for_more_information(string):
  pattern = '(?<==== For more information\n\n)((\s*)(.+)(\s*))+?'
  g = re.search(pattern, string)
  try:
    start = g.start()
    # assumes this is the last section in descrition so we use len(string) as last index
    end = len(string)
  except:
    return ""
  return string[start:end].rstrip()



# gets cvss3.1 level impact and assigns equivalent long string name 
# in  -> "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L"
# out -> ('Local', 'High', 'High', 'High', 'Required', 'Unchange', 'Low', 'Low', 'Low')
def get_cvss(cvss):
  # initialize cvss variables
  AV, AC, PR, PR, UI, S, C, I, A = "","","","","","","","",""
  try:
    AV = cvss[re.search('/AV:', cvss).span()[1]]
    AC = cvss[re.search('/AC:', cvss).span()[1]]
    PR = cvss[re.search('/PR:', cvss).span()[1]]
    UI = cvss[re.search('/UI:', cvss).span()[1]]
    S = cvss[re.search('/S:', cvss).span()[1]]
    C = cvss[re.search('/C:', cvss).span()[1]]
    I = cvss[re.search('/I:', cvss).span()[1]]
    A = cvss[re.search('/A:', cvss).span()[1]]
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

