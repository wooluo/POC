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
  script_id(126582);
  script_version("1.3");
  script_cvs_date("Date: 2019/08/16 15:34:48");

  script_cve_id(
    "CVE-2019-1001",
    "CVE-2019-1004",
    "CVE-2019-1056",
    "CVE-2019-1059",
    "CVE-2019-1063",
    "CVE-2019-1104"
  );
  script_bugtraq_id(
    108979,
    108982,
    109006,
    109007,
    109008,
    109009
  );
  script_xref(name:"MSKB", value:"4507434");
  script_xref(name:"MSKB", value:"4507462");
  script_xref(name:"MSKB", value:"4507449");
  script_xref(name:"MSKB", value:"4507448");
  script_xref(name:"MSKB", value:"4507452");
  script_xref(name:"MSFT", value:"MS19-4507434");
  script_xref(name:"MSFT", value:"MS19-4507462");
  script_xref(name:"MSFT", value:"MS19-4507449");
  script_xref(name:"MSFT", value:"MS19-4507448");
  script_xref(name:"MSFT", value:"MS19-4507452");

  script_name(english:"Security Updates for Internet Explorer (July 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Internet Explorer installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Internet Explorer installation on the remote host is
missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - A remote code execution vulnerability exists when
    Internet Explorer improperly accesses objects in memory.
    The vulnerability could corrupt memory in such a way
    that an attacker could execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2019-1063)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Internet Explorer. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2019-1004, CVE-2019-1056, CVE-2019-1059)

  - A remote code execution vulnerability exists in the way
    that Microsoft browsers access objects in memory. The
    vulnerability could corrupt memory in a way that could
    allow an attacker to execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2019-1104)

  - A remote code execution vulnerability exists in the way
    the scripting engine handles objects in memory in
    Microsoft browsers. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2019-1001)");
  # https://support.microsoft.com/en-us/help/4507434/cumulative-security-update-for-internet-explorer
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4507462/windows-server-2012-update-kb4507462
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4507449/windows-7-update-kb4507449
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4507448/windows-8-1-update-kb4507448
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4507452/windows-server-2008-update-kb4507452
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4507434
  -KB4507448
  -KB4507449
  -KB4507452
  -KB4507462");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1001");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS19-07';
kbs = make_list(
  '4507434',
  '4507452',
  '4507448',
  '4507462',
  '4507449'
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
os = get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0',  win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname)
 audit(AUDIT_OS_SP_NOT_VULN);
if ("Vista" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8.1 / Windows Server 2012 R2
  # Internet Explorer 11
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.19400", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4507434") ||

  # Windows Server 2012
  # Internet Explorer 10
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.22799", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"4507434") ||
  # Internet Explorer 11
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"11.0.9600.19400", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4507434") ||
  
  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.19400", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4507434") ||

  # Windows Server 2008
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.21352", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"4507434")
)
{
  report =  '\nNote: The fix for this issue is available in either of the following updates:\n';
  report += '  - KB4507434 : Cumulative Security Update for Internet Explorer\n';
  if(os == "6.3")
  {
    report += '  - KB4507448 : Windows 8.1 / Server 2012 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS19-07', kb:'4507448', report);
  }
  else if(os == "6.2")
  {
    report += '  - KB4507462 : Windows Server 2012 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS19-07', kb:'4507462', report);
  }
  else if(os == "6.1")
  {
    report += '  - KB4507449 : Windows 7 / Server 2008 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS19-07', kb:'4507449', report);
  }
  else if(os == "6.0")
  {
    report += '  - KB4507452 : Windows Server 2008 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS19-07', kb:'4507452', report);
  }
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
