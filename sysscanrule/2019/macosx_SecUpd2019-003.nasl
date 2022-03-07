#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125151);
  script_version("1.5");
  script_cvs_date("Date: 2019/07/25 16:22:16");

  script_cve_id(
    "CVE-2018-4456",
    "CVE-2019-6237",
    "CVE-2019-8560",
    "CVE-2019-8568",
    "CVE-2019-8569",
    "CVE-2019-8571",
    "CVE-2019-8574",
    "CVE-2019-8576",
    "CVE-2019-8577",
    "CVE-2019-8583",
    "CVE-2019-8584",
    "CVE-2019-8585",
    "CVE-2019-8586",
    "CVE-2019-8587",
    "CVE-2019-8589",
    "CVE-2019-8590",
    "CVE-2019-8591",
    "CVE-2019-8592",
    "CVE-2019-8594",
    "CVE-2019-8595",
    "CVE-2019-8596",
    "CVE-2019-8597",
    "CVE-2019-8598",
    "CVE-2019-8600",
    "CVE-2019-8601",
    "CVE-2019-8602",
    "CVE-2019-8603",
    "CVE-2019-8604",
    "CVE-2019-8605",
    "CVE-2019-8606",
    "CVE-2019-8607",
    "CVE-2019-8608",
    "CVE-2019-8609",
    "CVE-2019-8610",
    "CVE-2019-8611",
    "CVE-2019-8615",
    "CVE-2019-8616",
    "CVE-2019-8619",
    "CVE-2019-8622",
    "CVE-2019-8623",
    "CVE-2019-8628",
    "CVE-2019-8629",
    "CVE-2019-8634",
    "CVE-2019-8635"
  );
  script_xref(name:"APPLE-SA", value:"HT210119");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2019-05-09");

  script_name(english:"macOS and Mac OS X Multiple Vulnerabilities (Security Update 2019-003)");
  script_summary(english:"Checks the presence of Security Update 2019-003.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS or Mac OS X security update that fixes multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The remote host is running Mac OS X 10.12.6 or Mac OS X 10.13.6 and is missing a security update. It is, therefore,
affected by multiple vulnerabilities :

  - An application may be able to read restricted memory (CVE-2019-8603, CVE-2019-8560)

  - An application may be able to execute arbitrary code with system privileges (CVE-2019-8635, CVE-2019-8616,
    CVE-2019-8629, CVE-2018-4456, CVE-2019-8604, CVE-2019-8574, CVE-2019-8569)

  - An application may be able to execute arbitrary code with kernel privileges (CVE-2019-8590)

  - Processing a maliciously crafted audio file may lead to arbitrary code execution (CVE-2019-8592)

  - Processing a maliciously crafted movie file may lead to arbitrary code execution (CVE-2019-8585)

  - A malicious application may bypass Gatekeeper checks (CVE-2019-8589)

  - A malicious application may be able to read restricted memory (CVE-2019-8560, CVE-2019-8598)

  - A user may be unexpectedly logged in to another users account (CVE-2019-8634)

  - A local user may be able to load unsigned kernel extensions (CVE-2019-8606)

  - A malicious application may be able to execute arbitrary code with system privileges (CVE-2019-8605)

  - A local user may be able to cause unexpected system termination or read kernel memory (CVE-2019-8576)

  - An application may be able to cause unexpected system termination or write kernel memory (CVE-2019-8591)

  - An application may be able to gain elevated privileges (CVE-2019-8577)

  - A maliciously crafted SQL query may lead to arbitrary code execution (CVE-2019-8600)

  - A malicious application may be able to elevate privileges (CVE-2019-8602)

  - A local user may be able to modify protected parts of the file system (CVE-2019-8568)

  - Processing maliciously crafted web content may lead to arbitrary code execution (CVE-2019-6237, CVE-2019-8571,
    CVE-2019-8583, CVE-2019-8584, CVE-2019-8586, CVE-2019-8587, CVE-2019-8594, CVE-2019-8595, CVE-2019-8596,
    CVE-2019-8597, CVE-2019-8601,CVE-2019-8608, CVE-2019-8609, CVE-2019-8610, CVE-2019-8611, CVE-2019-8615,
    CVE-2019-8619, CVE-2019-8622, CVE-2019-8623, CVE-2019-8628)

  - Processing maliciously crafted web content may result in the disclosure of process memory (CVE-2019-8607)

Note that GizaNE has not tested for this issue but has instead relied
only on the operating system's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT210119");
  script_set_attribute(attribute:"solution", value:"Install Security Update 2019-003 or later for 10.12.x or Security
Update 2019-003 or later for 10.13.x");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-4456");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
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

patch = "2019-003";

packages = get_kb_item_or_exit("Host/MacOSX/packages/boms", exit_code:1);
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
  if (patch_found) exit(0, "The host has Security Update " + patch + " or later installed and is therefore not affected.");
}

report =  '\n  Missing security update : ' + patch;
report += '\n  Installed security BOMs : ';
if (sec_boms_report) report += str_replace(find:'\n', replace:'\n                            ', string:sec_boms_report);
else report += 'n/a';
report += '\n';

security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
