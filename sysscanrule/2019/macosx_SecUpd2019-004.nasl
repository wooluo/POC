#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127055);
  script_version("1.3");
  script_cvs_date("Date: 2019/08/22  6:00:04");

  script_cve_id(
    "CVE-2018-16860",
    "CVE-2018-19860",
    "CVE-2019-8641",
    "CVE-2019-8644",
    "CVE-2019-8646",
    "CVE-2019-8648",
    "CVE-2019-8649",
    "CVE-2019-8656",
    "CVE-2019-8657",
    "CVE-2019-8658",
    "CVE-2019-8660",
    "CVE-2019-8661",
    "CVE-2019-8662",
    "CVE-2019-8663",
    "CVE-2019-8666",
    "CVE-2019-8667",
    "CVE-2019-8669",
    "CVE-2019-8670",
    "CVE-2019-8671",
    "CVE-2019-8672",
    "CVE-2019-8673",
    "CVE-2019-8676",
    "CVE-2019-8677",
    "CVE-2019-8678",
    "CVE-2019-8679",
    "CVE-2019-8680",
    "CVE-2019-8681",
    "CVE-2019-8683",
    "CVE-2019-8684",
    "CVE-2019-8685",
    "CVE-2019-8686",
    "CVE-2019-8687",
    "CVE-2019-8688",
    "CVE-2019-8689",
    "CVE-2019-8690",
    "CVE-2019-8691",
    "CVE-2019-8692",
    "CVE-2019-8693",
    "CVE-2019-8694",
    "CVE-2019-8695",
    "CVE-2019-8697",
    "CVE-2019-13118"
  );
  script_xref(name:"APPLE-SA", value:"HT210348");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2019-07-17");
  script_xref(name:"IAVA", value:"2019-A-0260");

  script_name(english:"macOS Sierra / High Sierra Multiple Vulnerabilities (Security Update 2019-004)");
  script_summary(english:"Checks the presence of Security Update 2019-004.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS or Mac OS X security update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running Mac OS X 10.12.6 or Mac OS X 10.13.6 
and is missing a security update. It is, therefore, affected by
multiple vulnerabilities :

  - An application may be able to read restricted memory
    (CVE-2019-8691, CVE-2019-8692, CVE-2019-8693)

  - Extracting a zip file containing a symbolic link to an
    endpoint in an NFS mount that is attacker controlled may
    bypass Gatekeeper (CVE-2019-8656)

  - A remote attacker may be able to cause arbitrary code
    execution (CVE-2019-8648, CVE-2018-19860, CVE-2019-8661)

  - A remote attacker may be able to leak memory
    (CVE-2019-8646, CVE-2019-8663)

  - A remote attacker may be able to cause unexpected
    application termination or arbitrary code execution
    ( CVE-2019-8641, CVE-2019-8660)

  - An application may be able to execute arbitrary code
    with system privileges (CVE-2019-8695, CVE-2019-8697)

  - An issue existed in Samba that may allow attackers to
    perform unauthorized actions by intercepting
    communications between services (CVE-2018-16860)

  - An application may be able to execute arbitrary code
    with kernel privileges (CVE-2019-8694)

  - A remote attacker may be able to view sensitive
    information (CVE-2019-13118)

  - An attacker may be able to trigger a use-after-free in
    an application deserializing an untrusted NSDictionary
    (CVE-2019-8662)

  - Visiting a malicious website may lead to address bar
    spoofing (CVE-2019-8670)

  - The encryption status of a Time Machine backup may be
    incorrect (CVE-2019-8667)

  - Parsing a maliciously crafted office document may lead
    to an unexpected application termination or arbitrary
    code execution (CVE-2019-8657)

  - Processing maliciously crafted web content may lead to
    universal cross site scripting (CVE-2019-8649, 
    CVE-2019-8658, CVE-2019-8690)

  - Processing maliciously crafted web content may lead to
    arbitrary code execution (CVE-2019-8644, CVE-2019-8666,
    CVE-2019-8669, CVE-2019-8671, CVE-2019-8672,
    CVE-2019-8673, CVE-2019-8676, CVE-2019-8677,
    CVE-2019-8678, CVE-2019-8679, CVE-2019-8680,
    CVE-2019-8681, CVE-2019-8683, CVE-2019-8684,
    CVE-2019-8685, CVE-2019-8686, CVE-2019-8687,
    CVE-2019-8688, CVE-2019-8689)

Note that GizaNE has not tested for this issue but has instead
relied only on the operating system's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT210348");
  script_set_attribute(attribute:"solution", value:
"Install Security Update 2019-004 or later for 10.12.x or 10.13.x.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19860");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages/boms");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Compare 2 patch numbers to determine if patch requirements are satisfied.
# Return true if this patch or a later patch is applied
# Return false otherwise
function check_patch(year, number)
{
  local_var p_split = split(patch, sep:"-");
  local_var p_year  = int( p_split[0]);
  local_var p_num   = int( p_split[1]);

  if (year >  p_year) return TRUE;
  else if (year <  p_year) return FALSE;
  else if (number >=  p_num) return TRUE;
  else return FALSE;
}

get_kb_item_or_exit("Host/local_checks_enabled");
os = get_kb_item_or_exit("Host/MacOSX/Version");

if (!preg(pattern:"Mac OS X 10\.1[2-3]\.", string:os))
  audit(AUDIT_OS_NOT, "Mac OS X 10.12.x / 10.13.x");

patch = '2019-004';

packages = get_kb_item_or_exit('Host/MacOSX/packages/boms', exit_code:1);
sec_boms_report = pgrep(
  pattern:"^com\.apple\.pkg\.update\.(security\.|os\.SecUpd).*bom$",
  string:packages
);
sec_boms = split(sec_boms_report, sep:'\n');

foreach package (sec_boms)
{
  # Grab patch year and number
  matches = pregmatch(pattern:"[^0-9](20[0-9][0-9])[-.]([0-9]{3})[^0-9]", string:package);
  if (empty_or_null(matches)) continue;
  if (empty_or_null(matches[1]) || empty_or_null(matches[2]))
    continue;

  patch_found = check_patch(year:int(matches[1]), number:int(matches[2]));
  if (patch_found) exit(0, 'The host has Security Update ' + patch + ' or later installed and is therefore not affected.');
}

report =  '\n  Missing security update : ' + patch;
report += '\n  Installed security BOMs : ';
if (sec_boms_report) report += str_replace(find:'\n', replace:'\n                            ', string:sec_boms_report);
else report += 'n/a';
report += '\n';

security_report_v4(port:0, severity:SECURITY_WARNING, extra:report);
