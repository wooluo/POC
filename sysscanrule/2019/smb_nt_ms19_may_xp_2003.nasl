#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125073);
  script_version("1.5");
  script_cvs_date("Date: 2019/08/23 10:01:45");

  script_cve_id("CVE-2019-0708");
  script_bugtraq_id(108273);
  script_xref(name:"MSKB", value:"4500331");
  script_xref(name:"MSFT", value:"MS19-4500331");

  script_name(english:"Microsoft Security Advisory 4500331: Guidance for older platforms (XP / 2003) (BlueKeep)");
  script_summary(english:"Checks the versions of system files.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by a unspecified flaw that exists in the Remote
Desktop Protocol (RDP) service. An unauthenticated, remote attacker
can exploit this, via a specially crafted application, to execute
arbitrary code with full user privileges.");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0708
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP and 2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0708");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

kbs = make_list('4500331');

bulletin = 'MS19-05';

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'2,3', win2003:'2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = FALSE;
if ('XP' >< productname)
{
  if (
    # Windows XP SP3 (x86)
    hotfix_is_vulnerable(os:"5.1", sp:3, file:"termdd.sys", version:"5.1.2600.7701", min_version:"5.1.2600.5000", dir:"\system32\drivers", bulletin:bulletin, kb:"4500331", arch:"x86") ||
    # Windows XP SP2 (x64)
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"win32k.sys", version:"5.2.3790.6787", min_version:"5.2.3790.3000", dir:"\system32\drivers", bulletin:bulletin, kb:"4500331", arch:"x64")
  ) vuln = TRUE;
}
else if ('2003' >< productname)
{
  if (
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"termdd.sys", version:"5.2.3790.6787", min_version:"5.2.3790.3000", dir:"\system32\drivers", bulletin:bulletin, kb:"4500331")
  ) vuln = TRUE;
}

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
