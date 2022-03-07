#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121392);
  script_version("1.4");
  script_cvs_date("Date: 2019/07/16 10:54:26");

  script_cve_id(
    "CVE-2018-4452",
    "CVE-2018-4467",
    "CVE-2019-6200",
    "CVE-2019-6202",
    "CVE-2019-6205",
    "CVE-2019-6208",
    "CVE-2019-6209",
    "CVE-2019-6210",
    "CVE-2019-6213",
    "CVE-2019-6214",
    "CVE-2019-6218",
    "CVE-2019-6220",
    "CVE-2019-6221",
    "CVE-2019-6224",
    "CVE-2019-6225",
    "CVE-2019-6230",
    "CVE-2019-6231"
  );
  script_bugtraq_id(
    106694,
    106693
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2019-1-22-2");

  script_name(english:"macOS 10.13.6 Multiple Vulnerabilities (Security Update 2019-001)");
  script_summary(english:"Checks for the presence of Security Update 2019-001");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a macOS security update that fixes
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running macOS 10.13.6 and is missing a security
update. It is therefore, affected by multiple vulnerabilities in 
the following components:

  - Bluetooth
  - Core Media
  - CoreAnimation
  - FaceTime
  - Hypervisor
  - Intel Graphics Driver
  - IOKit
  - Kernel
  - libxpc
  - QuartzCore");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT209446");
  # https://lists.apple.com/archives/security-announce/2019/Jan/msg00001.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Install Security Update 2019-001 or later for 10.13.6.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6210");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/25");

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
  patch = "17G5019";

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
  if (patch_found) exit(0, "The host has Security Update 2019-001 (17G5019) or later installed and is therefore not affected.");
}

report =  '\n  Missing security update : 2019-001';
report += '\n  Installed security BOMs : ';
if (sec_boms_report) report += str_replace(find:'\n', replace:'\n                            ', string:sec_boms_report);
else report += 'n/a';
report += '\n';

security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
