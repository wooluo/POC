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
  script_id(125255);
  script_version("1.4");
  script_cvs_date("Date: 2019/07/12 12:39:17");

  script_cve_id("CVE-2019-0727");
  script_bugtraq_id(108225);

  script_xref(name:"MSKB", value:"4489639");
  script_xref(name:"MSFT", value:"MS19-4489639");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (May 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing a security
update. It is, therefore, affected by an elevation of privilege
vulnerability exists when the Diagnostics Hub Standard Collector
or the Visual Studio Standard Collector allows file deletion in
arbitrary locations. (CVE-2019-0727)");
  # https://support.microsoft.com/en-us/help/4489639/description-of-the-security-update-for-the-elevation-of-privilege-vuln
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes-v15.0
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes#15.9.12
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/visualstudio/install/visual-studio-build-numbers-and-release-dates?view=vs-2019
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB4489639 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0727");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_visual_studio_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible","installed_sw/Microsoft Visual Studio");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('audit.inc');
include('misc_func.inc');
include('install_func.inc');
include('global_settings.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');


get_kb_item_or_exit('installed_sw/Microsoft Visual Studio');

port = kb_smb_transport();
appname = 'Microsoft Visual Studio';

installs = get_installs(app_name:appname, exit_if_not_found:TRUE);

report = '';

foreach install (installs[1])
{
  version = install['version'];
  path = install['path'];
  prod = install['Product'];

  fix = '';
  # VS 2015 Up3
  # File Check change: using file 'StandardCollector.Service.exe'
  if (version =~ '^14\\.0\\.')
  {
    fix = '14.0.27533.0';
    fver = hotfix_get_fversion(path:path + 'Team Tools\\DiagnosticsHub\\Collector\\StandardCollector.Service.exe');
    if (fver['error'] != HCF_OK)
      continue;
    fversion = join(sep:'.', fver['value']);
    if (ver_compare(ver:fversion, fix:fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path + 'Team Tools\\DiagnosticsHub\\Collector\\StandardCollector.Service.exe' +
        '\n  Installed version : ' + fversion +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # VS 2017 (15.0)
  if (prod == '2017' && version =~ '^15\\.0\\.')
  {
    fix = '15.0.26228.84';

    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }

  # VS 2017 version 15.9
  # On 15.7.5, it asks to update to 15.9.7.
  else if (prod == '2017' && version =~ '^15\\.[1-9]\\.')
  {
    fix = '15.9.28307.665';

    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }

#  Uncomment after VS2019 detection is in order
#  # VS 2019 Version 16.0
#  else if (prod == '2019' && version =~ '^16\\.0\\.')
#  {
#    fix = '16.0.28803.452';
#    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
#    {
#      report +=
#        '\n  Path              : ' + path +
#        '\n  Installed version : ' + version +
#        '\n  Fixed version     : ' + fix +
#        '\n';
#    }
#  }

}

if (empty(report)) audit(AUDIT_INST_VER_NOT_VULN, appname);
security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
