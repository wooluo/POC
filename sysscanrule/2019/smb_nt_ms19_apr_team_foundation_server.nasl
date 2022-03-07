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
  script_id(123953);
  script_version("1.3");
  script_cvs_date("Date: 2019/05/15 19:00:42");

  script_cve_id(
    "CVE-2019-0857",
    "CVE-2019-0866",
    "CVE-2019-0867",
    "CVE-2019-0868",
    "CVE-2019-0869",
    "CVE-2019-0870",
    "CVE-2019-0871",
    "CVE-2019-0874",
    "CVE-2019-0875"
  );
  script_xref(name:"IAVA", value:"2019-A-0108");

  script_name(english:"Security Updates for Microsoft Team Foundation Server / Azure DevOps Server (April 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Team Foundation Server or Azure DevOps Server
installation on the remote host is affected by ");
  script_set_attribute(attribute:"description", value:
"The Microsoft Team Foundation Server or Azure DevOps Server
installation on the remote host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - An elevation of privilege vulnerability exists when
    Azure DevOps Server 2019 does not properly enforce
    project permissions. An attacker who exploited the
    vulnerability could add GitHub repositories to a project
    without having the proper access granted to their
    account. (CVE-2019-0875)

  - A spoofing vulnerability that could allow a security
    feature bypass exists in when Team Foundation Server
    does not properly sanitize user provided input. An
    attacker who exploited the vulnerability could trick a
    user into loading a page containing malicious content.
    An authenticated attacker could exploit the
    vulnerability by sending a specially crafted payload to
    the Team Foundation Server, which would get executed in
    the context of the user every time a user visits the
    compromised page.  (CVE-2019-0857)

  - A spoofing vulnerability exists in Microsoft Team
    Foundation Server when it fails to properly handle web
    requests. An attacker who successfully exploited the
    vulnerability could perform script or content injection
    attacks, and attempt to trick the user into disclosing
    sensitive information. An attacker could also redirect
    the user to a malicious website that could spoof content
    or the vulnerability could be used as a pivot to chain
    an attack with other vulnerabilities in web services.
    (CVE-2019-0869)

  - A Cross-site Scripting (XSS) vulnerability exists when
    Team Foundation Server does not properly sanitize user
    provided input. An authenticated attacker could exploit
    the vulnerability by sending a specially crafted payload
    to the Team Foundation Server, which will get executed
    in the context of the user every time a user visits the
    compromised page. The attacker who successfully
    exploited the vulnerability could then perform cross-
    site scripting attacks on affected systems and run
    script in the security context of the current user. The
    attacks could allow the attacker to read content that
    the attacker is not authorized to read, execute
    malicious code, and use the victim's identity to take
    actions on the site on behalf of the user, such as
    change permissions and delete content. The security
    update addresses the vulnerability by ensuring that Team
    Foundation Server sanitizes user inputs. (CVE-2019-0866,
    CVE-2019-0867, CVE-2019-0868, CVE-2019-0870,
    CVE-2019-0871, CVE-2019-0874)
");
  # https://devblogs.microsoft.com/devops/april-security-release-patches-available-for-azure-devops-server-2019-tfs-2018-3-2-tfs-2018-1-2-tfs-2017-3-1-and-the-release-of-tfs-2015-4-2/
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/tfs2015-update4-vs
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/tfs2017-update3
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/tfs2018-update1
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/tfs2018-update3
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/azure/devops/server/release-notes/azuredevops2019
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following updates to address these issues:
  - Team Foundation Server 2015 Update 4.1
  - Team Foundation Server 2017 Update 3.1 w/ patch
  - Team Foundation Server 2018 Update 1.2 w/ patch
  - Team Foundation Server 2018 Update 3.2 w/ patch
  - Azure DevOps Server 2019 RTW w/ patch

Please refer to the vendor guidance to determine the version and patch
to apply.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0875");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_team_foundation_server");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:azure_devops_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies(
    "microsoft_team_foundation_server_installed.nasl",
    "smb_hotfixes.nasl",
    "ms_bulletin_checks_possible.nasl"
  );
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS19-04';

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, 'Failed to determine the location of %windir%.');

registry_init();

port = kb_smb_transport();

installs = get_installs(app_name:'Microsoft Team Foundation Server', exit_if_not_found:TRUE);

foreach install (installs[1])
{
  vuln = FALSE;
  xss = FALSE;
  path = install['path'];
  update = install['Update'];
  release = install['Release'];

  # Those without update mappings
  if (empty_or_null(update) || !release)
    audit(AUDIT_HOST_NOT, 'affected');

  if (release == '2015')
  {
    # All 2015 should upgrade to 2015 Update 4.2
    if (ver_compare(ver:update, fix:'4.2', minver:'0', strict:FALSE) < 0)
    {
      xss = TRUE;
      vuln = TRUE;
      hotfix_add_report('Team Foundation Server 2015 prior to Update 4.2 is vulnerable. Ensure\n' +
                        'the installation is updated to Update 4.2', bulletin:bulletin);
    }
  }
  else if (release == '2017')
  {
    # All 2017 should upgrade to 2017 Update 3.1 w/patch
    path = hotfix_append_path(path:path, value:'Application Tier\\Web Services\\bin');
    if (hotfix_check_fversion(file:'Microsoft.TeamFoundation.Server.WebAccess.Admin.dll',
                              version:'15.117.28728.0',
                              min_version:'15.0.0.0',
                              path:path,
                              product:'Microsoft Team Foundation Server 2017 Update 3.1') == HCF_OLDER ||
       ver_compare(ver:update, fix:'3.1', minver:'0', strict:FALSE) < 0)
    {
      xss = TRUE;
      vuln = TRUE;
      hotfix_add_report('Team Foundation Server 2017 prior to Update 3.1 with patch is\n' +
                        'vulnerable. Ensure the installation is on Update 3.1 and apply the\n' +
                        'vendor patch.', bulletin:bulletin);
    }
  }
  # 2018 RTW -> 2018 Update 1.2
  else if (release == '2018' && ver_compare(ver:update, fix:'1.2', minver:'0', strict:FALSE) <= 0)
  {
    path = hotfix_append_path(path:path, value:'Application Tier\\Web Services\\bin');
    if (hotfix_check_fversion(file:'Microsoft.TeamFoundation.Server.WebAccess.Admin.dll',
                              version:'16.122.28801.2',
                              min_version:'16.0.0.0',
                              path:path,
                              product:'Microsoft Team Foundation Server 2018 Update 1.2') == HCF_OLDER ||
        ver_compare(ver:update, fix:'1.2', minver:'0', strict:FALSE) < 0)
    {
      xss = TRUE;
      vuln = TRUE;
      hotfix_add_report('Team Foundation Server 2018 prior to Update 1.2 with patch is\n' + 
                        'vulnerable. Ensure the installation is on Update 1.2 and apply the\n' + 
                        'vendor patch.', bulletin:bulletin);
    }
  }
  # 2018 Update 3.2
  else if (release == '2018' && ver_compare(ver:update, fix:'3.2', minver:'2', strict:FALSE) <= 0)
  {
    path = hotfix_append_path(path:path, value:'Application Tier\\Web Services\\bin');
    if (hotfix_check_fversion(file:'Microsoft.TeamFoundation.WorkItemTracking.Web.dll',
                              version:'16.131.28728.4',
                              min_version:'16.131.0.0',
                              path:path,
                              product:'Microsoft Team Foundation Server 2018 Update 3.2') == HCF_OLDER ||
        ver_compare(ver:update, fix:'3.2', minver:'2', strict:FALSE) < 0)
    {
      xss = TRUE;
      vuln = TRUE;
      hotfix_add_report('Team Foundation Server 2018 prior to Update 3.2 with patch is\n' + 
                        'vulnerable. Ensure you are on Update 3.2 and apply the vendor patch.', bulletin:bulletin);
    }
  }
  else if (release == '2019' && update == '0')
  {
    path = hotfix_append_path(path:path, value:'Application Tier\\Web Services\\bin');
    if (hotfix_check_fversion(file:'Microsoft.TeamFoundation.Server.WebAccess.VersionControl.dll',
                              version:'17.143.28804.3',
                              min_version:'17.0.0.0',
                              path:path,
                              product:'Microsoft Azure DevOps Server 2019 RTW') == HCF_OLDER)
    {
      xss = TRUE;
      vuln = TRUE;
      hotfix_add_report('Azure DevOps Server 2019 RTW is vulnerable. Ensure you apply the\n' + 
                        'vendor patch.', bulletin:bulletin);
    }
  }
}

if (vuln)
{
  if (xss) replace_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
