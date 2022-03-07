include("compat.inc");

if (description)
{
  script_id(119017);
  script_version("1.2");
  script_cvs_date("Date: 2019/02/14 17:26:20");

  script_cve_id("CVE-2018-8529", "CVE-2018-8602");
  script_bugtraq_id(105895, 105910);


  script_name(english:"Security Updates for Microsoft Team Foundation Server (November 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Team Foundation Server installation on the remote host
is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Team Foundation Server installation on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities :

  - A remote code execution vulnerability exists when Team Foundation
    Server (TFS) does not enable basic authorization on the
    communication between the TFS and Search services. Without basic
    authorization, an attacker could run certain commands on the
    Search service. (CVE-2018-8529)

  - A Cross-site Scripting (XSS) vulnerability exists when Team
    Foundation Server does not properly sanitize user provided input.
    An authenticated attacker could exploit the vulnerability by
    sending a specially crafted payload to the Team Foundation
    Server, which will get executed in the context of the user every
    time a user visits the compromised page. (CVE-2018-8602)");
  #
  script_set_attribute(attribute:"see_also", value:"https://blogs.msdn.microsoft.com/devops/2018/11/05/security-fixes-for-team-foundation-server/");
  #
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/visualstudio/releasenotes/tfs2017-update3");
  #
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/visualstudio/releasenotes/tfs2018-update1");
  #
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/visualstudio/releasenotes/tfs2018-update3");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following updates to address these issues:
  - Team Foundation Server 2017 Update 3.1 w/ patch
  - Team Foundation Server 2018 Update 1.1 w/ patch
  - Team Foundation Server 2018 Update 3 w/ patch
  - Team Foundation Server 2018 Update 3.1

Please refer to the vendor guidance to determine the version and patch
to apply.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8529");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_team_foundation_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by WebRAY, Inc. ");

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

bulletin = "MS18-11";

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
    if (hotfix_check_fversion(file:"Microsoft.TeamFoundation.Server.WebAccess.Admin.dll", version:"15.117.28224.0", min_version:"15.0.0.0", path:path, product:"Microsoft Team Foundation Server 2017 Update 3.1") == HCF_OLDER)
    {
      vuln = TRUE;
      xss = TRUE;
      hotfix_add_report("Team Foundation Server 2017 prior to Update 3.1 with patch is vulnerable. Ensure the system is on Update 3.1 and apply the vendor patch.", bulletin:bulletin);
    }
  }
  # 2018 RTW -> 2018 Update 1.1 should upgrade to 2018 Update 1.1 w/ patch
  else if (release == "2018" && ver_compare(ver:update, fix:"1.1", minver:"0", strict:FALSE) <= 0)
  {
    path = hotfix_append_path(path:path, value:"Application Tier\Web Services\bin");
    if (hotfix_check_fversion(file:"Microsoft.TeamFoundation.Server.WebAccess.Admin.dll", version:"16.122.28226.4", min_version:"16.0.0.0", path:path, product:"Microsoft Team Foundation Server 2018 Update 1.1") == HCF_OLDER)
    {
      vuln = TRUE;
      xss = TRUE;
      hotfix_add_report("Team Foundation Server 2018 prior to Update 1.1 with patch is vulnerable. Ensure the system is on Update 1.1 and apply the vendor patch.", bulletin:bulletin);
    }
  }
  # 2018 Update 2 or 2018 Update 3 should upgrade to 2018 Update 3 w/ patch or 2018 Update 3.1
  else if (release == "2018" && ver_compare(ver:update, fix:"3", minver:"2", strict:FALSE) <= 0)
  {
    path = hotfix_append_path(path:path, value:"Application Tier\Web Services\bin");
    if (hotfix_check_fversion(file:"Microsoft.TeamFoundation.Server.WebAccess.Admin.dll", version:"16.131.28224.5", min_version:"16.131.0.0", path:path, product:"Microsoft Team Foundation Server 2018 Update 3") == HCF_OLDER)
    {
      vuln = TRUE;
      xss = TRUE;
      hotfix_add_report("Team Foundation Server 2018 prior to Update 3.1 is vulnerable. Ensure you are on Update 3 and apply the vendor patch or upgrade to Update 3.1.", bulletin:bulletin);
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
