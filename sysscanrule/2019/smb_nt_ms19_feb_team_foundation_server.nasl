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
  script_id(122185);
  script_version("1.3");
  script_cvs_date("Date: 2019/03/15 15:35:01");

  script_cve_id("CVE-2019-0742", "CVE-2019-0743");
  script_bugtraq_id(106967, 106970);

  script_name(english:"Security Updates for Microsoft Team Foundation Server (February 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Team Foundation Server installation on the remote host
is affected by multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Team Foundation Server installation on the remote
host is missing security updates. It is, therefore, affected
by multiple cross-site scripting vulnerabilities. An authenticated
attacker could exploit the vulnerability by sending a specially crafted
payload to the Team Foundation Server, which will get executed in the
context of the user every time a user visits the compromised page.
");
  # https://blogs.msdn.microsoft.com/devops/2019/02/12/february-security-release-team-foundation-server-2018-update-3-2-patch-1-is-available/
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/tfs2018-update3
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following updates to address these issues:
  - Team Foundation Server 2018 Update 3.2 w/ patch 1

Please refer to the vendor guidance for information on the appropriate
version and patch to apply.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0742");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_team_foundation_server");
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

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS19-02";

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, "Failed to determine the location of %windir%.");

registry_init();

port = kb_smb_transport();

installs = get_installs(app_name:"Microsoft Team Foundation Server", exit_if_not_found:TRUE);

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

  # 2018 Update 3.2 w/ Patch 1
  if (release == "2018" && ver_compare(ver:update, fix:"3.2", minver:"2", strict:FALSE) <= 0)
  {
    path = hotfix_append_path(path:path, value:"Application Tier\Web Services\bin");
    if (hotfix_check_fversion(file:"Microsoft.TeamFoundation.WorkItemTracking.Web.dll", version:"16.131.28605.6", min_version:"16.131.0.0", path:path, product:"Microsoft Team Foundation Server 2018 Update 3.2") == HCF_OLDER ||
        ver_compare(ver:update, fix:"3.2", minver:"2", strict:FALSE) < 0)
    {
      xss = TRUE;
      vuln = TRUE;
      hotfix_add_report("Team Foundation Server 2018 prior to Update 3.2 with patch is vulnerable. Ensure you are on Update 3.2 and apply the vendor patch.", bulletin:bulletin);
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
