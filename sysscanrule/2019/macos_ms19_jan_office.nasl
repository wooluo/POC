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
  script_id(121542);
  script_version("1.3");
  script_cvs_date("Date: 2019/02/26 11:11:16");

  script_cve_id(
    "CVE-2019-0585",
    "CVE-2019-0561"
  );
  script_bugtraq_id(
    106339,
    106392
  );

  script_name(english:"Security Update for Microsoft Office (Jan 2019) (macOS)");
  script_summary(english:"Checks the version of Microsoft Office.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS or Mac OS X host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office application installed on the remote macOS
or Mac OS X host is missing a security update. It is, therefore,
affected by the following vulnerabilities:

  - A remote code execution vulnerability exists in Microsoft Word
    software when it fails to properly handle objects in memory. An
    attacker who successfully exploited the vulnerability could use a
    specially crafted file to perform actions in the security context
    of the current user. For example, the file could then take actions
    on behalf of the logged-on user with the same permissions as the
    current user.

    To exploit the vulnerability, a user must open a specially crafted
    file with an affected version of Microsoft Word software. In an
    email attack scenario, an attacker could exploit the vulnerability
    by sending the specially crafted file to the user and convincing
    the user to open the file. In a web-based attack scenario, an
    attacker could host a website (or leverage a compromised website
    that accepts or hosts user-provided content) that contains a
    specially crafted file that is designed to exploit the
    vulnerability. However, an attacker would have no way to force the
    user to visit the website. Instead, an attacker would have to
    convince the user to click a link, typically by way of an
    enticement in an email or Instant Messenger message, and then
    convince the user to open the specially crafted file.

    The security update addresses the vulnerability by correcting how
    Microsoft Word handles files in memory. (CVE-2019-0585)

  - An information disclosure vulnerability exists when Microsoft Word
    macro buttons are used improperly. An attacker who successfully
    exploited this vulnerability could read arbitrary files from a
    targeted system. To exploit the vulnerability, an attacker could
    craft a special document file and convince the user to open it.
    An attacker must know the file location whose data they wish to
    exfiltrate. The update addresses the vulnerability by changing the
    way certain Word functions handle security warnings.
    (CVE-2019-0561)");

  # https://docs.microsoft.com/en-us/officeupdates/release-notes-office-2016-mac#january-2019-release
  script_set_attribute(attribute:"see_also",value:"");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0585
  script_set_attribute(attribute:"see_also",value:"");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2019-0561
  script_set_attribute(attribute:"see_also",value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office for
Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0585");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/01");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_for_mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
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

apps = make_list(
  "Microsoft Word",
  "Microsoft Excel",
  "Microsoft PowerPoint",
  "Microsoft OneNote",
  "Microsoft Outlook"
);

#2019
min_ver_19 = '16.17.0';
fix_ver_19 = '16.21.0';
fix_disp_19 = '16.21.0 (19011500)';
fix_disp_19_excel = '16.21.0 (19012303)';

#2016
min_ver_16 = '16';
fix_ver_16 = '16.16.6';
fix_disp_16 = '16.16.6 (19011400)';
report = '';

os = get_kb_item_or_exit("Host/MacOSX/Version");

for(i = 0; i < len(apps); i++)
{
  app = apps[i];
  installs = get_installs(app_name:app);
  if (isnull(installs[1])) continue;

  for(j = 0; j < len(installs[1]); j++)
  {
    install = installs[1][j];
    version = install['version'];
    
    if (ver_compare(ver:version, minver:min_ver_19, fix:fix_ver_19, strict:FALSE) < 0)
    {
      app_label = app + ' for Mac 2019';
      fix_disp = fix_disp_19;
      if (app == "Microsoft Excel") fix_disp = fix_disp_19_excel;

      report +=
        '\n\n  Product           : ' + app_label +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix_disp;
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
