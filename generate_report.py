import json
from pygments import highlight, lexers, formatters
from utils import convert_desc, get_symbol, find_line, get_cwes, get_cvss
from utils import get_impact, get_patches, get_references, get_workarounds, get_for_more_information


def get_classified_vunerabilities(raw_data):
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

def generate_lows(data):
  (_, _, _, lows) = get_classified_vunerabilities(data)
  # print(highlight(json.dumps(lows, indent=2), lexers.JsonLexer(), formatters.TerminalFormatter()))
  report = []
  for index, data in enumerate(lows):
    result = generate(data, index+1)
    report.append(result)
  return report

def generate_mediums(data):
  (_, _, med, _) = get_classified_vunerabilities(data)
  # print(highlight(json.dumps(med[9], indent=2), lexers.JsonLexer(), formatters.TerminalFormatter()))
  report = []
  for i, data in enumerate(med):
    if i < 9:
      # result = generate(data, i+1)
      # report.append(result)
      pass
    elif i == 9:
      print(highlight(json.dumps(data, indent=1), lexers.JsonLexer(), formatters.TerminalFormatter()))
      break
  return report

def generate_highs(data):
  (_, highs, _, _) = get_classified_vunerabilities(data)
  # print(highlight(json.dumps(highs, indent=2), lexers.JsonLexer(), formatters.TerminalFormatter()))
  report = []
  for index, data in enumerate(highs):
    result = generate(data, index+1)
    report.append(result)
  return report

def generate_criticals(data):
  (criticals, _, _, _) = get_classified_vunerabilities(data)
  # print(highlight(json.dumps(highs, indent=2), lexers.JsonLexer(), formatters.TerminalFormatter()))
  report = []
  for index, data in enumerate(criticals):
    result = generate(data, index+1)
    report.append(result)
  return report

def generate(data, index):

  # asciidoc variables
  url_cwe = "{url-cwe}"
  url_nist = "{url-nist}"
  url_ghsa = "{url-ghsa}"
  url_repo = "{url-repo}"
  url_blob = "{url-blob}"
  file_dir = "{ctf-dir}"
  
  title,severity,symbol,scope,package,description,desc,CVSS,score,recommendation,file,language,line,linenums,ghsa_id,cve_id,cwes,impact,patches,workarounds,references,more_information,vulnerable_version,patched_version = (None,)*24

  try:
    # used template varibles
    title = data["security_advisory"]["summary"]
    severity = data["security_advisory"]["severity"].title()
    symbol = get_symbol(severity)
    scope = data["dependency"]["scope"]
    package = data["dependency"]["package"]["name"]
    description = data["security_advisory"]["description"]
    desc = convert_desc(description)
    CVSS =  data["security_advisory"]["cvss"]["vector_string"]
    score = data["security_advisory"]["cvss"]["score"]
    recommendation = "<RECOMMENDATION>"
    file = data["dependency"]["manifest_path"]
    language = "<LANGUAGE>"
    line = find_line(package, "./CTFs/" + file)
    linenums = "L" + str(line -1) + "-L" + str(line + 3)
    ghsa_id = data["security_advisory"]["ghsa_id"]
    cve_id = data["security_advisory"]["cve_id"]
    cwes = get_cwes(data["security_advisory"]["cwes"])
    impact = get_impact(desc)
    patches = get_patches(desc)
    workarounds = get_workarounds(desc)
    references = get_references(desc)
    more_information = get_for_more_information(desc)
    language = data["dependency"]["package"]["ecosystem"]
    vulnerable_version = data["security_vulnerability"]["vulnerable_version_range"]
    patched_version = None
  except ValueError as e:
      print('Caught this error: ' + repr(e))

  # Sometimes the severitiy is not detected
  if not symbol:
    symbol =  data["security_vulnerability"]["severity"][0].upper() + "-"

  if data["security_vulnerability"]["first_patched_version"]:
    patched_version = data["security_vulnerability"]["first_patched_version"]["identifier"]


  # descturcture results from `get_cvss()`
  (AV, AC, PR, PR, UI, S, C, I, A) = get_cvss(CVSS)

  template = f""""""

  # template format for .asciidoc report
  if impact and CVSS:
    template = f"""## tag::{index}[]
== {symbol}{index} {title}

Tags: `{scope}`, Weaknesses: {cwes}, CVE ID: {url_nist}{cve_id}[{cve_id}], GHSA ID: {url_ghsa}{ghsa_id}[{ghsa_id}]

.File {url_repo}{url_blob}{file}#{linenums}[{file}#{linenums}]
[source, {language}, %linenums]
----
include::{file_dir}{file}[lines={line-1}..{line+3}]
----

{impact}

=== Impact: {severity} {score} / 10

.{CVSS}
[%header]
|===
2+| CVSS base metrics
| Attack vector | {AV}
| Attack complexity | {AC}
| Privileges required | {PR}
| User interaction | {UI}
| Scope | {S}
| Confidentiality | {C}
| Integrity | {I}
| Availability  | {A}
|===

=== Patches

{patches}

{recommendation}

=== References

{references}

## end::{index}[]
"""
  if impact and not CVSS:
    # print([i["url"] for i in data["security_advisory"]["references"]])
    refs = data["security_advisory"]["references"]
    if len(refs) > 5:
      refs = data["security_advisory"]["references"][0:5]
    references = "* " + "\n* ".join([i["url"] for i in refs])
    template = f"""## tag::{index}[]
== {symbol}{index} {title}
Tags: `{scope}`, Weaknesses: GHSA ID: {url_ghsa}{ghsa_id}[{ghsa_id}] {cwes}

.File {url_repo}{url_blob}{file}#{linenums}[{file}#{linenums}]
[source, {language}, %linenums]
----
include::{file_dir}{file}[lines={line-1}..{line+3}]
----

{impact}

=== References

{references}

=== Recommendation

This bug has been patched and users should upgrade to {package} {patched_version}

## end::{index}[]
"""

  if not impact and not CVSS:
    impact = convert_desc(description)
    # print([i["url"] for i in data["security_advisory"]["references"]])
    refs = data["security_advisory"]["references"]
    if len(refs) > 5:
      refs = data["security_advisory"]["references"][0:5]
    references = "* " + "\n* ".join([i["url"] for i in refs])
    template = f"""## tag::{index}[]
== {symbol}{index} {title}
Tags: `{scope}`, Weaknesses: GHSA ID: {url_ghsa}{ghsa_id}[{ghsa_id}] {cwes}

.File {url_repo}{url_blob}{file}#{linenums}[{file}#{linenums}]
[source, {language}, %linenums]
----
include::{file_dir}{file}[lines={line-1}..{line+3}]
----

{impact}

=== References

{references}

=== Recommendation

Consider alternatives of this dependency.

## end::{index}[]
"""

  if CVSS and not impact:
    impact = convert_desc(description)
    # print([i["url"] for i in data["security_advisory"]["references"]])
    refs = data["security_advisory"]["references"]
    if len(refs) > 5:
      refs = data["security_advisory"]["references"][0:5]
    references = "* " + "\n* ".join([i["url"] for i in refs])
    template = f"""## tag::{index}[]
== {symbol}{index} {title}
Tags: `{scope}`, Weaknesses: GHSA ID: {url_ghsa}{ghsa_id}[{ghsa_id}] {cwes}

.File {url_repo}{url_blob}{file}#{linenums}[{file}#{linenums}]
[source, {language}, %linenums]
----
include::{file_dir}{file}[lines={line-1}..{line+3}]
----

{impact}

=== Impact: {severity} {score} / 10

.{CVSS}
[%header]
|===
2+| CVSS base metrics
| Attack vector | {AV}
| Attack complexity | {AC}
| Privileges required | {PR}
| User interaction | {UI}
| Scope | {S}
| Confidentiality | {C}
| Integrity | {I}
| Availability  | {A}
|===

=== References

{references}

=== Recommendation

Consider alternatives of this dependency.

## end::{index}[]
"""

  return template


