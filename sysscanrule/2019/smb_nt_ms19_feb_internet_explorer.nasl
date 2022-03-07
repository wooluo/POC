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
  script_id(122131);
  script_version("1.4");
  script_cvs_date("Date: 2019/03/15 15:35:01");

    script_cve_id(
    "CVE-2019-0606",
    "CVE-2019-0654",
    "CVE-2019-0663",
    "CVE-2019-0676"
  );
  script_xref(name:"MSKB", value:"4487000");
  script_xref(name:"MSKB", value:"4487023");
  script_xref(name:"MSKB", value:"4486563");
  script_xref(name:"MSKB", value:"4486474");
  script_xref(name:"MSKB", value:"4487025");
  script_xref(name:"MSFT", value:"MS19-4487000");
  script_xref(name:"MSFT", value:"MS19-4487023");
  script_xref(name:"MSFT", value:"MS19-4486563");
  script_xref(name:"MSFT", value:"MS19-4486474");
  script_xref(name:"MSFT", value:"MS19-4487025");
 
  script_name(english:"Security Updates for Internet Explorer (February 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Internet Explorer installation on the remote host is
missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Internet Explorer installation on the remote host is
missing a security update. It is, therefore, affected by the
following vulnerabilities :

  - A remote code execution vulnerability exists when
    Internet Explorer accesses objects in memory. The
    vulnerability could corrupt memory in such a way that
    an attacker could execute arbitrary code in the context
    of the current user. (CVE-2019-0606)

  - A spoofing vulnerability exists when Microsoft browsers
    improperly handles specific redirects. An attacker who 
    successfully exploited this vulnerability could trick a 
    user into believing that the user was on a legitimate 
    website. (CVE-2019-0654)

  - An information disclosure vulnerability exists when
    Internet Explorer improperly handles objects in memory.
    An attacker who successfully exploited this vulnerability 
    could test for the presence of files on disk. For an 
    attack to be successful, an attacker must persuade a user 
    to open a malicious website. (CVE-2019-0676)

  - An information disclosure vulnerability exists when the
    Windows kernel improperly initializes objects in memory.
    To exploit this vulnerability, an authenticated attacker
    could run a specially crafted application. An attacker who
    successfully exploited this vulnerability could obtain
    information to further compromise the user's system. 
    (CVE-2019-0663)");

  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4487000
  -KB4487023
  -KB4486563
  -KB4486474
  -KB4487025");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0606");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/12");

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

bulletin = 'MS19-02';
kbs = make_list(
  '4487000',
  '4486474',
  '4487023',
  '4486563',
  '4487025'
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
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.19262", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4486474") ||

  # Windows Server 2012
  # Internet Explorer 10
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.22671", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"4486474") ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.19262", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4486474") ||

  # Windows Server 2008
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.21312", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"4486474")
)
{
  report =  '\nNote: The fix for this issue is available in either of the following updates:\n';
  report += '  - KB4486474 : Cumulative Security Update for Internet Explorer\n';
  if(os == "6.3")
  {
    report += '  - KB4487000 : Windows 8.1 / Server 2012 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS19-02', kb:'4487000', report);
  }
  else if(os == "6.2")
  {
    report += '  - KB4487025 : Windows Server 2012 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS19-02', kb:'4487025', report);
  }
  else if(os == "6.1")
  {
    report += '  - KB4486563 : Windows 7 / Server 2008 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS19-02', kb:'4486563', report);
  }
  else if(os == "6.0")
  {
    report += '  - KB4487023 : Windows Server 2008 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS19-02', kb:'4487023', report);
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
