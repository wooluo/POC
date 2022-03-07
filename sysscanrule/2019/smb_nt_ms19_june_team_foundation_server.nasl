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
  script_id(125833);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/11 19:23:32");

  script_cve_id("CVE-2019-0996");

  script_name(english:"Security Updates for Azure DevOps Server (June 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Azure DevOps Server is affected by an XSRF vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Azure DevOps Server is missing a security update. It is,
therefore, affected by a cross-site request forgery (XSRF)
vulnerability:

  - A spoofing vulnerability exists in Azure DevOps Server when it
    improperly handles requests to authorize applications, resulting
    in a cross-site request forgery. An attacker who successfully
    exploited this vulnerability could bypass OAuth protections and
    register an application on behalf of the targeted user. To
    exploit this vulnerability, an attacker would need to create a
    page specifically designed to cause a cross-site request. The
    attacker would then need to convince a targeted user to click a
    link to the malicious page. (CVE-2019-0996)");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released Azure DevOps Server 2019 Update 0.1 to
address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0996");

  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0996
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/azure/devops/server/release-notes/azuredevops2019?view=azure-devops#azure-devops-server-201901-release-date-may-21-2019
  script_set_attribute(attribute:"see_also", value:"");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:azure_devops_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_team_foundation_server_installed.nasl","smb_hotfixes.nasl","ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS19-06';

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
  path = install['path'];
  update = install['Update'];
  release = install['Release'];

  # Those without update mappings
  if (empty_or_null(update) || !release)
    audit(AUDIT_HOST_NOT, 'affected');

  # Only 2019 affected, patched in Update 0.1
  if (release == '2019' && update == '0')
  {
    path = hotfix_append_path(path:path, value:'Application Tier\\Web Services\\bin');
    if (hotfix_check_fversion(file:'Microsoft.TeamFoundation.Server.WebAccess.VersionControl.dll',
                              version:'17.143.28912.1',
                              min_version:'17.0.0.0',
                              path:path,
                              product:'Microsoft Azure DevOps Server 2019 RTW') == HCF_OLDER)
    {
      vuln = TRUE;
      hotfix_add_report('Azure DevOps Server 2019 prior to Update 0.1 is vulnerable. Ensure\n' +
                        'the installation is updated to Update 0.1.', bulletin:bulletin);
    }
  }
}

if (vuln)
{
  replace_kb_item(name:'www/'+port+'/XSRF', value:TRUE);
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
