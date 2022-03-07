#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include("compat.inc");

if (description)
{
  script_id(127894);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/14 16:41:08");

  script_cve_id(
    "CVE-2019-1148",
    "CVE-2019-1149",
    "CVE-2019-1151",
    "CVE-2019-1153",
    "CVE-2019-1201",
    "CVE-2019-1205");

  script_name(english:"Security Update for Microsoft Office (August 2019) (macOS)");
  script_summary(english:"Checks the version of Microsoft Office.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS or Mac OS X host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office application installed on the remote macOS or Mac OS X host is missing a security update. It is,
therefore, affected by multiple vulnerabilities:

  - A remote code execution vulnerability exists in Microsoft Word due to improper handling of objects in memory. An
    unauthenticated, remote attacker can exploit this, by convincing a user to open a specially crafted file, to execute
    arbitrary commands in the security context of the current user. (CVE-2019-1201, CVE-2019-1205)

  - An information disclosure vulnerability exists in Microsoft Windows Graphics due to improper handling of objects in
    memory. An authenticated, local attacker can exploit this, by running a specially crafted application to obtain
    information for further compromise of the system. (CVE-2019-1148, CVE-2019-1153)

  - A remote code execution vulnerability exists in Windows font library due to improper handling of embedded fonts. An
    unauthenticated, remote attacker can exploit this, by convincing a user to visit a specially crafted website or
    open a specially crafted file, to execute arbitrary commands. (CVE-2019-1149, CVE-2019-1151)
");
  # https://docs.microsoft.com/en-us/officeupdates/release-notes-office-2016-mac#august-2019-release
  script_set_attribute(attribute:"see_also",value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1201");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/14");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:onenote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_office_installed.nbin");
  script_require_keys("Host/MacOSX/Version");
  script_require_ports(
    "installed_sw/Microsoft Word",
    "installed_sw/Microsoft Excel",
    "installed_sw/Microsoft PowerPoint",
    "installed_sw/Microsoft OneNote",
    "installed_sw/Microsoft Outlook"
  );

  exit(0);
}
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("vcf.inc");

os = get_kb_item_or_exit("Host/MacOSX/Version");
apps = make_list(
  'Microsoft Word',
  'Microsoft Excel',
  'Microsoft PowerPoint',
  'Microsoft OneNote',
  'Microsoft Outlook'
);
report = '';

#2016
min_ver_16 = '16';
fix_ver_16 = '16.16.13';
fix_disp_16 = '16.16.13 (19081100)';

#2019
min_ver_19 = '16.17.0';
fix_ver_19 = '16.28';
fix_disp_19 = '16.28 (19081202)';

foreach app (apps)
{
  installs = get_installs(app_name:app);
  if (isnull(installs[1]))
    continue;

  foreach install (installs[1])
  {
    version = install['version'];

    if (ver_compare(ver:version, minver:min_ver_19, fix:fix_ver_19, strict:FALSE) < 0)
    {
      app_label = app + ' for Mac 2019';
      report +=
        '\n\n  Product           : ' + app_label +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix_disp_19;
    }
    else if (ver_compare(ver:version, minver:min_ver_16, fix:fix_ver_16, strict:FALSE) < 0)
    {
      app_label = app + ' for Mac 2016';
      report +=
        '\n\n  Product           : ' + app_label +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix_disp_16;
    }
  }
}
if (empty(report))
  audit(AUDIT_HOST_NOT, "affected");

if (os =~ "^Mac OS X 10\.[0-9](\.|$)")
  report += '\n  Note              : Update will require Mac OS X 10.10.0 or later.\n';

security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
