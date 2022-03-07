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
  script_id(126641);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/15 11:09:49");

  script_cve_id("CVE-2019-1072","CVE-2019-1076");
  script_bugtraq_id(108930, 108933);
  script_xref(name:"IAVA", value:"2019-A-0227");

  script_name(english:"Security Updates for Microsoft Team Foundation Server and Azure DevOps Server (July 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Team Foundation or Azure DevOps Server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Team Foundation or Azure DevOps Server is missing security
updates. It is, therefore, affected by multiple vulnerabilities :

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
    Foundation Server sanitizes user inputs. (CVE-2019-1076)

  - A remote code execution vulnerability exists when Azure
    DevOps Server and Team Foundation Server (TFS)
    improperly handle user input. An attacker who
    successfully exploited the vulnerability could execute
    code on the target server in the context of the DevOps
    or TFS service account.  (CVE-2019-1072)");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following updates to address these issues:
  - Team Foundation Server 2010 SP1 with patch 1
  - Team Foundation Server 2012 Update 4 with patch 1
  - Team Foundation Server 2013 Update 5 with patch 1
  - Team Foundation Server 2015 Update 4.2 with patch 2
  - Team Foundation Server 2017 Update 3.1 with patch 6
  - Team Foundation Server 2018 Update 1.2 with patch 5
  - Team Foundation Server 2018 Update 3.2 with patch 5
  - Azure DevOps Server 2019 Update 0.1 with patch 1

Please refer to the vendor guidance to determine the version and patch
to apply.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1072");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:azure_devops_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_team_foundation_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_team_foundation_server_installed.nasl","smb_hotfixes.nasl","ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('audit.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('misc_func.inc');
include('install_func.inc');
include('spad_log_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS19-07';

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

  spad_log(message: 'path: ' + path + '\n update: ' + update + '\n release: ' + release);
  # Those without update mappings
  if (empty_or_null(update) || !release)
    audit(AUDIT_HOST_NOT, 'affected');

  if (release == '2010' && ver_compare(ver:update, fix:'1.2', minver:'0', strict:FALSE) <= 0)
  {
    path = hotfix_append_path(path:path, value:'Application Tier\\Web Services\\bin');
    if (hotfix_check_fversion(file:'Microsoft.TeamFoundation.Framework.Server.dll',
                              version:'10.0.40219.504',
                              min_version:'10.0.0.0',
                              path:path,
                              product:'Microsoft Team Foundation Server 2010 SP1') == HCF_OLDER)
    {
      xss = TRUE;
      vuln = TRUE;
      hotfix_add_report('Team Foundation Server 2010 prior to SP1 patch 1 is vulnerable. Ensure\n' +
                        'the installation is updated to Update SP1 patch 1.', bulletin:bulletin);
    }
  }
  else if (release == '2012' && ver_compare(ver:update, fix:'4', minver:'0', strict:FALSE) <= 0)
  {
    path = hotfix_append_path(path:path, value:'Application Tier\\Web Services\\bin');
    if (hotfix_check_fversion(file:'Microsoft.TeamFoundation.WorkItemTracking.Server.DataServices.dll',
                              version:'11.0.61243.400',
                              min_version:'11.0.0.0',
                              path:path,
                              product:'Microsoft Team Foundation Server 2012 Update 4') == HCF_OLDER)
    {
      xss = TRUE;
      vuln = TRUE;
      hotfix_add_report('Team Foundation Server 2010 prior to Update 4 patch 1 is vulnerable. Ensure\n' +
                        'the installation is updated to Update 4 patch 1.', bulletin:bulletin);
    }
  }
  else if (release == '2013' && ver_compare(ver:update, fix:'5', minver:'0', strict:FALSE) <= 0)
  {
    path = hotfix_append_path(path:path, value:'Application Tier\\Web Services\\bin');
    if (hotfix_check_fversion(file:'Microsoft.TeamFoundation.WorkItemTracking.Server.DataServices.dll',
                              version:'12.0.40681.1',
                              min_version:'12.0.0.0',
                              path:path,
                              product:'Microsoft Team Foundation Server 2013 Update 5') == HCF_OLDER)
    {
      xss = TRUE;
      vuln = TRUE;
      hotfix_add_report('Team Foundation Server 2013 prior to Update 5 patch 1 is vulnerable. Ensure\n' +
                        'the installation is updated to Update 5 patch 1.', bulletin:bulletin);
    }

  }
  if (release == '2015' && ver_compare(ver:update, fix:'4.2', minver:'0', strict:FALSE) <= 0)
  {
    path = hotfix_append_path(path:path, value:'Application Tier\\Web Services\\bin');
    if (hotfix_check_fversion(file:'Microsoft.TeamFoundation.Framework.Server.dll',
                              version:'14.114.29025.0',
                              min_version:'14.0.0.0',
                              path:path,
                              product:'Microsoft Team Foundation Server 2015 Update 4.2') == HCF_OLDER)
    {
      xss = TRUE;
      vuln = TRUE;
      hotfix_add_report('Team Foundation Server 2015 prior to Update 4.2 patch 2 is vulnerable. Ensure\n' +
                        'the installation is updated to Update 4.2 patch 2.', bulletin:bulletin);
    }
  }
  else if (release == '2017' && ver_compare(ver:update, fix:'3.1', minver:'0', strict:FALSE) <= 0)
  {
    path = hotfix_append_path(path:path, value:'Application Tier\\Web Services\\bin');
    if (hotfix_check_fversion(file:'Microsoft.TeamFoundation.Server.WebAccess.Admin.dll',
                              version:'15.117.29024.0',
                              min_version:'15.0.0.0',
                              path:path,
                              product:'Microsoft Team Foundation Server 2017 Update 3.1') == HCF_OLDER)
    {
      xss = TRUE;
      vuln = TRUE;
      hotfix_add_report('Team Foundation Server 2017 prior to Update 3.1 patch 6 is vulnerable. Ensure\n' +
                        'the installation is updated to Update 3.1 patch 6', bulletin:bulletin);
    }
  }
  # 2018 RTW -> 2018 Update 1.2 (122)
  else if (release == '2018' && ver_compare(ver:update, fix:'1.2', minver:'0', strict:FALSE) <= 0)
  {
    path = hotfix_append_path(path:path, value:'Application Tier\\Web Services\\bin');
    if (hotfix_check_fversion(file:'Microsoft.TeamFoundation.Server.WebAccess.Admin.dll',
                              version:'16.122.29017.5',
                              min_version:'16.0.0.0',
                              path:path,
                              product:'Microsoft Team Foundation Server 2018 Update 1.2') == HCF_OLDER)
    {
      xss = TRUE;
      vuln = TRUE;
      hotfix_add_report('Team Foundation Server 2018 prior to Update 1.2 patch 5 is vulnerable. Ensure\n' +
                        'the installation is updated to Update 4.2 patch 2', bulletin:bulletin);
     }
  }
  # 2018 Update 2 -> 2018 Update 3.2 (131)
  else if (release == '2018' && ver_compare(ver:update, fix:'3.2', minver:'2', strict:FALSE) <= 0)
  {
    path = hotfix_append_path(path:path, value:'Application Tier\\Web Services\\bin');
    if (hotfix_check_fversion(file:'Microsoft.TeamFoundation.WorkItemTracking.Web.dll',
                              version:'16.131.29019.4',
                              min_version:'16.131.0.0',
                              path:path,
                              product:'Microsoft Team Foundation Server 2018 Update 3.2') == HCF_OLDER)
    {
      xss = TRUE;
      vuln = TRUE;
      hotfix_add_report('Team Foundation Server 2018 prior to Update 3.2 patch 5 is vulnerable. Ensure\n' +
                        'the installation is updated to Update 3.2 patch 5', bulletin:bulletin);
     }
  }
  else if (release == '2019' && ver_compare(ver:update, fix:'0.1', minver:'0', strict:FALSE) <= 0)
  {
    path = hotfix_append_path(path:path, value:'Application Tier\\Web Services\\bin');
    if (hotfix_check_fversion(file:'Microsoft.TeamFoundation.WorkItemTracking.Server.DataServices.dll',
                              version:'17.143.29019.5',
                              min_version:'17.0.0.0',
                              path:path,
                              product:'Microsoft Azure DevOps Server 2019.0.1') == HCF_OLDER)
    {
      xss = TRUE;
      vuln = TRUE;
      hotfix_add_report('Azure DevOps Server 2019 prior to 2019.0.1 patch 1 is vulnerable. Ensure\n' +
                        'the installation is updated to 2019.0.1 patch 1.', bulletin:bulletin);
    }
  }
}

if (vuln)
{
  if (xss) replace_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
