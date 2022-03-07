#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123130);
  script_version("1.6");
  script_cvs_date("Date: 2019/07/29 13:07:49");

  script_cve_id(
    "CVE-2018-12015",
    "CVE-2018-18311",
    "CVE-2018-18313",
    "CVE-2019-8521",
    "CVE-2019-8522",
    "CVE-2019-8504",
    "CVE-2019-8527",
    "CVE-2019-8529",
    "CVE-2019-8555",
    "CVE-2019-6207",
    "CVE-2019-8510",
    "CVE-2019-8513",
    "CVE-2019-8520",
    "CVE-2019-8526",
    "CVE-2019-8561",
    "CVE-2019-8564"
  );
  script_bugtraq_id(
    104423,
    106072,
    106145
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2019-3-25-2");

  script_name(english:"macOS 10.13.6 Multiple Vulnerabilities (Security Update 2019-002)");
  script_summary(english:"Checks for the presence of Security Update 2019-002 (APPLE-SA-2019-3-25-2)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS security update that fixes
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running macOS 10.13.6 and is missing a security
update. It is therefore, affected by multiple vulnerabilities
including:

  - An application may be able to execute arbitrary code with kernel
    privileges. (CVE-2019-8529)

  - A local user may be able to read kernel memory. (CVE-2019-8504)

  - A malicious application may be able to determine kernel memory
    layout. (CVE-2019-6207, CVE-2019-8510)

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
"Install Security Update 2019-002 or later for 10.13.6.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-8529");
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


get_kb_item_or_exit("Host/local_checks_enabled");
os = get_kb_item_or_exit("Host/MacOSX/Version");

if (!preg(pattern:"Mac OS X 10\.(13\.6)([^0-9]|$)", string:os))
  audit(AUDIT_OS_NOT, "macOS 10.13.6");

if ("10.13.6" >< os)
  patch = "17G6029";

# Get sec/supplemental boms ; 10.13.x is using 'Supplemental' now
packages = get_kb_item_or_exit("Host/MacOSX/packages/boms", exit_code:1);
sec_boms_report = pgrep(
  pattern:"^com\.apple\.pkg\.update\.(security\.|os\.SecUpd|os\.10\.13\.6Supplemental\.).*bom$",
  string:packages
);
sec_boms = split(sec_boms_report, sep:'\n');

foreach package (sec_boms)
{
  # Grab ID string, e.g., grab '17G3025' from string like :
  # /System/Library/Receipts/com.apple.pkg.update.os.SecUpd2018-002Sierra.17G3025.bom
  matches = pregmatch(pattern:"Sierra\.([^.]+)\.bom$", string:package);
  if (empty_or_null(matches)) continue;
  if (empty_or_null(matches[1]))
    continue;

  if (matches[1] >= patch)
    patch_found = TRUE;
  if (patch_found) exit(0, "The host has Security Update 2019-002 (17G6029) or later installed and is therefore not affected.");
}

report =  '\n  Missing security update : 2019-002';
report += '\n  Installed security BOMs : ';
if (sec_boms_report) report += str_replace(find:'\n', replace:'\n                            ', string:sec_boms_report);
else report += 'n/a';
report += '\n';

security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
