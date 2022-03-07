#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123129);
  script_version("1.6");
  script_cvs_date("Date: 2019/07/29 13:07:49");

  script_cve_id(
    "CVE-2018-12015",
    "CVE-2018-18311",
    "CVE-2018-18313",
    "CVE-2019-6207",
    "CVE-2019-8540",
    "CVE-2019-8508",
    "CVE-2019-8510",
    "CVE-2019-8513",
    "CVE-2019-8520",
    "CVE-2019-8521",
    "CVE-2019-8522",
    "CVE-2019-8526",
    "CVE-2019-8527",
    "CVE-2019-8530",
    "CVE-2019-8555",
    "CVE-2019-8561",
    "CVE-2019-8564"
  );
  script_bugtraq_id(
    104423,
    106072,
    106145
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2019-3-25-2");

  script_name(english:"macOS and Mac OS X Multiple Vulnerabilities (Security Update 2019-002)");
  script_summary(english:"Checks for the presence of Security Update 2019-002.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS or Mac OS X security update that
fixes multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Mac OS X 10.12.6 and is missing a security
update. It is therefore, affected by multiple vulnerabilities
including:

  - A malicious application may be able to execute arbitrary code
    with kernel privileges. (CVE-2019-8555)

  - A malicious application may be able to determine kernel memory
    layout. (CVE-2019-6207, CVE-2019-8510)

  - A malicious application may be able to read restricted memory.
    (CVE-2019-8520)

  - 802.1X
  - DiskArbitration
  - Feedback Assistant
  - IOKit
  - IOKit SCSI
  - Kernel
  - PackageKit
  - Perl
  - Security
  - Time Machine
  - Wi-Fi");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT209600");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT209635");
 # https://lists.apple.com/archives/security-announce/2019/Mar/msg00001.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Install Security Update 2019-002 or later for 10.12.x.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8555");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mac OS X TimeMachine (tmdiagnose) Command Injection Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages/boms");

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

if (!preg(pattern:"Mac OS X 10\.12\.6([^0-9]|$)", string:os))
  audit(AUDIT_OS_NOT, "Mac OS X 10.12.6");

patch = "2019-002";

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
