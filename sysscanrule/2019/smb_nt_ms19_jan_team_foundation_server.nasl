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
  script_id(121189);
  script_version("1.3");
  script_cvs_date("Date: 2019/03/22 12:12:16");

  script_cve_id("CVE-2019-0646", "CVE-2019-0647");

  script_name(english:"Security Updates for Microsoft Team Foundation Server (January 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Team Foundation Server installation on the remote host
is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Team Foundation Server installation on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities:

  - A cross-site scripting (XSS) vulnerability exists when Team
  Foundation Server does not properly sanitize user provided input. An
  authenticated attacker could exploit the vulnerability by sending a
  specially crafted payload to the Team Foundation Server, which will
  get executed in the context of the user every time a user visits the
  compromised page. (CVE-2019-0646)

  - An information disclosure vulnerability exists when Team Foundation
  Server does not properly handle variables marked as secret. An
  authenticated attacker who successfully exploited this vulnerability
  could view variables that were hidden by other users. (CVE-2019-0647)
");
  # https://blogs.msdn.microsoft.com/devops/2019/01/15/team-foundation-server-security-updates/
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/tfs2017-update3
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/tfs2018-update1
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/visualstudio/releasenotes/tfs2018-update3
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following updates to address these issues:
  - Team Foundation Server 2017 Update 3.1 w/ patch
  - Team Foundation Server 2018 Update 1.2 w/ patch
  - Team Foundation Server 2018 Update 3.2

Please refer to the vendor guidance to determine the version and patch
to apply.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0647");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/15");

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

bulletin = "MS19-01";

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

  if (release == "2017")
  {
    # All 2017 should upgrade to 2017 Update 3.1 w/patch
    path = hotfix_append_path(path:path, value:"Application Tier\Web Services\bin");
    if (hotfix_check_fversion(file:"Microsoft.TeamFoundation.Server.WebAccess.Admin.dll", version:"15.117.28504.0", min_version:"15.0.0.0", path:path, product:"Microsoft Team Foundation Server 2017 Update 3.1") == HCF_OLDER ||
       ver_compare(ver:update, fix:"3.1", minver:"0", strict:FALSE) < 0)
    {
      xss = TRUE;
      vuln = TRUE;
      hotfix_add_report("Team Foundation Server 2017 prior to Update 3.1 with patch is vulnerable. Ensure the system is on Update 3.1 and apply the vendor patch.", bulletin:bulletin);
    }
  }
  # 2018 RTW -> 2018 Update 1.2
  else if (release == "2018" && ver_compare(ver:update, fix:"1.2", minver:"0", strict:FALSE) <= 0)
  {
    path = hotfix_append_path(path:path, value:"Application Tier\Web Services\bin");
    if (hotfix_check_fversion(file:"Microsoft.TeamFoundation.Server.WebAccess.Admin.dll", version:"16.122.28512.1", min_version:"16.0.0.0", path:path, product:"Microsoft Team Foundation Server 2018 Update 1.2") == HCF_OLDER ||
        ver_compare(ver:update, fix:"1.2", minver:"0", strict:FALSE) < 0)
    {
      xss = TRUE;
      vuln = TRUE;
      hotfix_add_report("Team Foundation Server 2018 prior to Update 1.2 with patch is vulnerable. Ensure the system is on Update 1.2 and apply the vendor patch.", bulletin:bulletin);
    }
  }
  # 2018 Update 3.2
 else if (release == "2018" && ver_compare(ver:update, fix:"3.2", minver:"2", strict:FALSE) < 0)
  {
    xss = TRUE;
    vuln = TRUE;
    hotfix_add_report("Team Foundation Server 2018 prior to Update 3.2 is vulnerable. Ensure you are on Update 3.2.", bulletin:bulletin);
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
