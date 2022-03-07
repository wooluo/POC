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
  script_id(125069);
  script_version("1.3");
  script_cvs_date("Date: 2019/06/13 17:57:55");

  script_cve_id(
    "CVE-2019-0884",
    "CVE-2019-0911",
    "CVE-2019-0918",
    "CVE-2019-0921",
    "CVE-2019-0930",
    "CVE-2019-0940"
  );
  script_xref(name:"MSKB", value:"4498206");
  script_xref(name:"MSKB", value:"4499149");
  script_xref(name:"MSKB", value:"4499151");
  script_xref(name:"MSKB", value:"4499164");
  script_xref(name:"MSKB", value:"4499171");
  script_xref(name:"MSFT", value:"MS19-4498206");
  script_xref(name:"MSFT", value:"MS19-4499149");
  script_xref(name:"MSFT", value:"MS19-4499151");
  script_xref(name:"MSFT", value:"MS19-4499164");
  script_xref(name:"MSFT", value:"MS19-4499171");

  script_name(english:"Security Updates for Internet Explorer (May 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Internet Explorer installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Internet Explorer installation on the remote host is
missing security updates. It is, therefore, affected by
multiple vulnerabilities :

  - An spoofing vulnerability exists when Internet Explorer
    improperly handles URLs. An attacker who successfully
    exploited this vulnerability could trick a user by
    redirecting the user to a specially crafted website. The
    specially crafted website could either spoof content or
    serve as a pivot to chain an attack with other
    vulnerabilities in web services.  (CVE-2019-0921)

  - A remote code execution vulnerability exists in the way
    that Microsoft browsers access objects in memory. The
    vulnerability could corrupt memory in a way that could
    allow an attacker to execute arbitrary code in the
    context of the current user. An attacker who
    successfully exploited the vulnerability could gain the
    same user rights as the current user.  (CVE-2019-0940)

  - A remote code execution vulnerability exists in the way
    the scripting engine handles objects in memory in
    Microsoft browsers. The vulnerability could corrupt
    memory in such a way that an attacker could execute
    arbitrary code in the context of the current user. An
    attacker who successfully exploited the vulnerability
    could gain the same user rights as the current user.
    (CVE-2019-0884, CVE-2019-0911, CVE-2019-0918)

  - An information disclosure vulnerability exists when
    Internet Explorer improperly handles objects in memory.
    An attacker who successfully exploited the vulnerability
    could obtain information to further compromise the users
    system.  (CVE-2019-0930)");
  # https://support.microsoft.com/en-us/help/4499171/windows-server-2012-update-kb4499171
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4498206/cumulative-security-update-for-internet-explorer-may-14-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4499164/windows-7-update-kb4499164
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4499151/windows-8-1-update-kb4499151
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4499149/windows-server-2008-update-kb4499149
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4498206
  -KB4499149
  -KB4499151
  -KB4499164
  -KB4499171
  ");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0940");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

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

bulletin = 'MS19-05';
kbs = make_list(
  '4499151',
  '4498206',
  '4499149',
  '4499164',
  '4499171'
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
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.19354", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4498206") ||

  # Windows Server 2012
  # Internet Explorer 10
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.22752", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"4498206") ||
  # Internet Explorer 11
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"11.0.9600.19354", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4498206") ||
  
  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.19354", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4498206") ||

  # Windows Server 2008
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.21334", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"4498206")
)
{
  report =  '\nNote: The fix for this issue is available in either of the following updates:\n';
  report += '  - KB4498206 : Cumulative Security Update for Internet Explorer\n';
  if(os == "6.3")
  {
    report += '  - KB4499151 : Windows 8.1 / Server 2012 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS19-05', kb:'4499151', report);
  }
  else if(os == "6.2")
  {
    report += '  - KB4499171 : Windows Server 2012 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS19-05', kb:'4499171', report);
  }
  else if(os == "6.1")
  {
    report += '  - KB4499164 : Windows 7 / Server 2008 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS19-05', kb:'4499164', report);
  }
  else if(os == "6.0")
  {
    report += '  - KB4499149 : Windows Server 2008 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS19-05', kb:'4499149', report);
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
