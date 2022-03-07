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
  script_id(126604);
  script_version("1.3");
  script_cvs_date("Date: 2019/08/20 15:35:10");

  script_cve_id("CVE-2019-1077", "CVE-2019-1079", "CVE-2019-1113");
  script_bugtraq_id(108931, 108977);

  script_xref(name:"MSKB", value:"4506161");
  script_xref(name:"MSKB", value:"4506162");
  script_xref(name:"MSKB", value:"4506163");
  script_xref(name:"MSKB", value:"4506164");
  script_xref(name:"MSFT", value:"MS19-4506161");
  script_xref(name:"MSFT", value:"MS19-4506162");
  script_xref(name:"MSFT", value:"MS19-4506163");
  script_xref(name:"MSFT", value:"MS19-4506164");
  script_xref(name:"IAVA", value:"2019-A-0225");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (July 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing security updates. It is, therefore, affected by multiple
vulnerabilities:

  - An information disclosure vulnerability exists when Visual Studio improperly parses XML input in certain
    settings files. An attacker who successfully exploited this vulnerability could read arbitrary files via an XML
    external entity (XXE) declaration. (CVE-2019-1079)

  - A remote code execution vulnerability exists in .NET software when the software fails to check the source
    markup of a file. An attacker who successfully exploited the vulnerability could run arbitrary code in the
    context of the current user. If the current user is logged on with administrative user rights, an attacker
    could take control of the affected system. An attacker could then install programs; view, change, or delete
    data; or create new accounts with full user rights. (CVE-2019-1113)

  - An elevation of privilege vulnerability exists when the Visual Studio updater service improperly handles file
    permissions. An attacker who successfully exploited this vulnerability overwrite arbitrary files with XML content
    in the security context of the local system. (CVE-2019-1077)");
  # https://support.microsoft.com/en-us/help/4506161/security-update-for-information-disclosure-vulnerability-in-vs-2010
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4506162/security-update-for-information-disclosure-vulnerability-in-vs-2012
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4506163/security-update-for-information-disclosure-vulnerability-in-vs-2013
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4506164/security-update-for-elevation-of-privilege-vulnerability-vs-2015
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes-v15.0#15.0.26228.92
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes#15.9.14
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes-v16.0#16.0.6
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/visualstudio/releases/2019/release-notes#16.1.6
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4506161
  -KB4506162
  -KB4506163
  -KB4506164");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1113");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

  # VS 2010 SP1
  if (version =~ '^10\\.0\\.')
  {
    fix = '10.0.40219.505';
    file = "Common7\IDE\QTAgent.exe";
    fver = hotfix_get_fversion(path:path + file);
    if (fver['error'] != 0)
      continue;
    if (empty_or_null(fver['value']))
      continue;
    fversion = join(sep:".", fver['value']);
    if (ver_compare(ver: fversion, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path + file +
        '\n  Installed version : ' + fversion +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # VS 2012 Up5
  else if (version =~ '^11\\.0\\.')
  {
    fix = '11.0.61241.400';
    file = "Common7\IDE\ReferenceAssemblies\v2.0\Microsoft.VisualStudio.QualityTools.Common.dll";
    fver = hotfix_get_fversion(path:path+file);
    if (fver['error'] != 0)
      continue;
    if (empty_or_null(fver['value']))
      continue;
    fversion = join(sep:".", fver['value']);
    if (ver_compare(ver: fversion, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path + file +
        '\n  Installed version : ' + fversion +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # VS 2013 Up5
  else if (version =~ '^12\\.0\\.')
  {
    patch_installed = false;
    foreach name (get_kb_list('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName'))
      if ('4506163' >< name)
        patch_installed = true;

    if (!patch_installed)
      report +=
        '\nNote: The fix for this issue is available in the following update:\n' +
        '\n  - KB4506163 : Security update for the information disclosure vulnerability in Microsoft Visual Studio 2013 Update 5: July 9, 2019\n' +
        '\n';
  }
  # VS 2015 Up3
  # File Check change: using file 'StandardCollector.Service.exe'
  else if (version =~ '^14\\.0\\.')
  {
    fix = '14.0.27536.0';
    file = "Common7\IDE\ReferenceAssemblies\v2.0\Microsoft.VisualStudio.QualityTools.Common.dll";
    fver = hotfix_get_fversion(path:path + file);
    if (fver['error'] != HCF_OK)
      continue;
    fversion = join(sep:'.', fver['value']);
    if (ver_compare(ver:fversion, fix:fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path + file +
        '\n  Installed version : ' + fversion +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
  # VS 2017 (15.0)
  else if (prod == '2017' && version =~ '^15\\.0\\.')
  {
    fix = '15.0.26228.92';

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
    fix = '15.9.28307.770';

    if (ver_compare(ver: version, fix: fix, strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix +
        '\n';
    }
  }
}

if (empty(report))
  audit(AUDIT_INST_VER_NOT_VULN, appname);

security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
