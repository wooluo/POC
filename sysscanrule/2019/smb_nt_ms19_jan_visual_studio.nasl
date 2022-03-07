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
  script_id(121065);
  script_version("1.2");
  script_cvs_date("Date: 2019/02/26  4:50:09");

  script_cve_id(
    "CVE-2019-0537",
    "CVE-2019-0546"
  );
  script_xref(name:"MSKB", value:"4476698");
  script_xref(name:"MSKB", value:"4476755");
  script_xref(name:"MSFT", value:"MS19-4476698");
  script_xref(name:"MSFT", value:"MS19-4476755");
  script_xref(name:"IAVA", value:"2019-A-0011");

  script_name(english:"Security Updates for Microsoft Visual Studio Products (January 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visual Studio Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visual Studio Products are missing a security
update. It is, therefore, affected by the following
vulnerability :

  - An information disclosure vulnerability exists when
    Visual Studio improperly discloses arbitrary file
    contents if the victim opens a malicious .vscontent
    file. An attacker who took advantage of this information
    disclosure could view arbitrary file contents from the
    computer where the victim launched Visual Studio. To
    take advantage of the vulnerability, an attacker would
    need to trick a user into opening a malicious .vscontent
    file using a vulnerable version of Visual Studio. An
    attacker would have no way to force a developer to
    produce this information disclosure. The security update
    addresses the vulnerability by correcting how Visual
    Studio loads .vscontent files. (CVE-2019-0537)

  - A remote code execution vulnerability exists in Visual
    Studio when the C++ compiler improperly handles specific
    combinations of C++ constructs. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights. Users whose accounts are configured to have
    fewer user rights on the system could be less impacted 
    than users who operate with administrative user rights.
    Exploitation of the vulnerability requires that a user 
    open a specially crafted file which was compiled with
    an affected version of Visual Studio. In an email
    attack scenario, an attacker could exploit the 
    vulnerability by sending a specially crafted project,
    or resource file, to the user and convince the user to
    open the file. (CVE-2019-0546)  
  ");
  # https://support.microsoft.com/en-us/help/4476698/information-disclosure-vulnerability-in-visual-studio
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4476755/description-of-the-security-update-for-the-information-disclosure
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/vs2017-relnotes
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  - KB4476698
  - KB4476755
  - Update 15.9.4 for Visual Studio 2017");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0537");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_set_attribute(attribute:"stig_severity",value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_visual_studio_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible","installed_sw/Microsoft Visual Studio");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("install_func.inc");
include("global_settings.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


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

  # VS 2010 SP1
  if (version =~ '^10\\.0\\.')
  {
    commonfiles = hotfix_get_commonfilesdirx86();
    if (!commonfiles) commonfiles = hotfix_get_commonfilesdir();

    if (!commonfiles) audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');
    if (commonfiles) path = hotfix_append_path(path:commonfiles, value:"\microsoft shared\MSEnv\");

    fver = hotfix_get_fversion(path:path + "VSContentInstaller.exe");
    if (fver['error'] != 0)
      continue;
    if (empty_or_null(fver['value']))
      continue;
    fversion = join(sep:".", fver['value']);
    if (ver_compare(ver: fversion, fix: '10.0.40219.501', strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path + "VSContentInstaller.exe" +
        '\n  Installed version : ' + fversion +
        '\n  Fixed version     : 10.0.40219.501' +
        '\n';
    }
  }
  # VS 2012 Up5
  else if (version =~ '^11\\.0\\.')
  {
    commonfiles = hotfix_get_commonfilesdirx86();
    if (!commonfiles) commonfiles = hotfix_get_commonfilesdir();

    if (!commonfiles) audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');

    fver = hotfix_get_fversion(path:path+"VSContentInstaller.exe");
    if (fver['error'] != 0)
      continue;
    if (empty_or_null(fver['value']))
      continue;
    fversion = join(sep:".", fver['value']);
    if (ver_compare(ver: fversion, fix: '11.0.61239.400', strict:FALSE) < 0)
    {
      report +=
        '\n  Path              : ' + path + "VSContentInstaller.exe" +
        '\n  Installed version : ' + fversion +
        '\n  Fixed version     : 11.0.61239.400' +
        '\n';
    }
  }

  # VS 2017 version 15.9
  # On 15.7.5, it asks to update to 15.9.5
  else if (prod == '2017' && version =~ '^15\\.[1-9]\\.')
  {
    fix = '15.9.28307.280';

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

if (report != '')
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
else
  audit(AUDIT_INST_VER_NOT_VULN, appname);
