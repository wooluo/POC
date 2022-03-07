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
  script_id(125828);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/12 12:39:17");

  script_cve_id(
    "CVE-2019-0920",
    "CVE-2019-0988",
    "CVE-2019-1005",
    "CVE-2019-1038",
    "CVE-2019-1055",
    "CVE-2019-1080",
    "CVE-2019-1081"
  );
  script_xref(name:"MSKB", value:"4503259");
  script_xref(name:"MSKB", value:"4503273");
  script_xref(name:"MSKB", value:"4503276");
  script_xref(name:"MSKB", value:"4503285");
  script_xref(name:"MSKB", value:"4503292");
  script_xref(name:"MSFT", value:"MS19-4503259");
  script_xref(name:"MSFT", value:"MS19-4503273");
  script_xref(name:"MSFT", value:"MS19-4503276");
  script_xref(name:"MSFT", value:"MS19-4503285");
  script_xref(name:"MSFT", value:"MS19-4503292");

  script_name(english:"Security Updates for Internet Explorer (June 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Internet Explorer installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Internet Explorer installation on the remote host is
missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - A remote code execution vulnerability exists in the way
    that Microsoft browsers access objects in memory. The
    vulnerability could corrupt memory in a way that could
    allow an attacker to execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2019-1038)

  - A remote code execution vulnerability exists in the way
    the scripting engine handles objects in memory in
    Microsoft browsers. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2019-0920, CVE-2019-1005, CVE-2019-1055,
    CVE-2019-1080)

  - An information disclosure vulnerability exists when
    affected Microsoft browsers improperly handle objects in
    memory. An attacker who successfully exploited this
    vulnerability could obtain information to further
    compromise the users system.  (CVE-2019-1081)

  - A remote code execution vulnerability exists in the way
    that the scripting engine handles objects in memory in
    Internet Explorer. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2019-0988)");
  # https://support.microsoft.com/en-us/help/4503276/june-11-2019-kb4503276-os-build-monthly-rollup
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4503273/windows-server-2008-update-kb4503273
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4503292/windows-7-update-kb4503292
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4503285/windows-server-2012-kb4503285
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4503259/cumulative-security-update-for-internet-explorer
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4503259
  -KB4503273
  -KB4503276
  -KB4503285
  -KB4503292
  ");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0988");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
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

bulletin = 'MS19-06';
kbs = make_list(
  '4503259',
  '4503273',
  '4503276',
  '4503285',
  '4503292'
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
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.19377", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4503259") ||

  # Windows Server 2012
  # Internet Explorer 10
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.22773", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"4503259") ||
  # Internet Explorer 11
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"11.0.9600.19377", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4503259") ||
  
  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.19377", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4503259") ||

  # Windows Server 2008
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.21342", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"4503259")
)
{
  report =  '\nNote: The fix for this issue is available in either of the following updates:\n';
  report += '  - KB4503259 : Cumulative Security Update for Internet Explorer\n';
  if(os == "6.3")
  {
    report += '  - KB4503276 : Windows 8.1 / Server 2012 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS19-06', kb:'4503276', report);
  }
  else if(os == "6.2")
  {
    report += '  - KB4503285 : Windows Server 2012 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS19-06', kb:'4503285', report);
  }
  else if(os == "6.1")
  {
    report += '  - KB4503292 : Windows 7 / Server 2008 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS19-06', kb:'4503292', report);
  }
  else if(os == "6.0")
  {
    report += '  - KB4503273 : Windows Server 2008 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS19-06', kb:'4503273', report);
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
