
#
# 
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include("compat.inc");

if (description)
{
  script_id(151597);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/13");

  script_cve_id(
    "CVE-2021-34446",
    "CVE-2021-34447",
    "CVE-2021-34448",
    "CVE-2021-34497"
  );
  script_xref(name:"MSKB", value:"5004233");
  script_xref(name:"MSKB", value:"5004289");
  script_xref(name:"MSKB", value:"5004294");
  script_xref(name:"MSKB", value:"5004298");
  script_xref(name:"MSKB", value:"5004305");
  script_xref(name:"MSFT", value:"MS21-5004233");
  script_xref(name:"MSFT", value:"MS21-5004289");
  script_xref(name:"MSFT", value:"MS21-5004294");
  script_xref(name:"MSFT", value:"MS21-5004298");
  script_xref(name:"MSFT", value:"MS21-5004305");

  script_name(english:"Security Updates for Internet Explorer (July 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Internet Explorer installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Internet Explorer installation on the remote host is
missing a security update. It is, therefore, affected by the following vulnerabilities:

  - A security bypass vulnerability exists in the HTML platforms component. An unauthenticated, remote attacker
    can exploit this to bypass security in order to gain full access to the system. (CVE-2021-34446)

  - A remote code execution vulnerability exists in the MSHTML platform. An unauthenticated, remote attacker
    can exploit this to bypass authentication and execute arbitrary commands. (CVE-2021-34447, CVE-2021-34497)

  - A memory corruption error exists in the scripting engine. An unauthenticated, remote attacker can exploit
    this to execute arbitrary commands. (CVE-2021-34448)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/topic/5004233");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/topic/5004289");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/topic/5004294");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/topic/5004298");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/topic/5004305");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5004233
  -KB5004289
  -KB5004294
  -KB5004298
  -KB5004305
");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34446");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

var bulletin = 'MS21-07';
var kbs = make_list(
  '5004233',
  '5004289',
  '5004294',
  '5004298',
  '5004305'
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
var os = get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0',  win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

var productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname)
 audit(AUDIT_OS_SP_NOT_VULN);
if ("Vista" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

var share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8.1 / Windows Server 2012 R2
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.20064", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"5004233") ||

  # Windows Server 2012
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"11.0.9600.20064", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"5004233") ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.20064", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"5004233") ||

  # Windows Server 2008
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.21575", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"5004233")
)
{
  var report =  '\nNote: The fix for this issue is available in either of the following updates:\n';
  report += '  - KB5004233 : Cumulative Security Update for Internet Explorer\n';

  if(os == "6.3")
  {
    report += '  - KB5004298 : Windows 8.1 / Server 2012 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:bulletin, kb:'5004298', report);
  }
  else if(os == "6.2")
  {
    report += '  - KB5004294 : Windows Server 2012 Monthly Rollup\n';
    hotfix_add_report(bulletin:bulletin, kb:'5004294', report);
  }
  else if(os == "6.1")
  {
    report += '  - KB5004289 : Windows 7 / Server 2008 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:bulletin, kb:'5004289', report);
  }
  else if(os == "6.0")
  {
    report += '  - KB5004305 : Windows Server 2008 Monthly Rollup\n';
    hotfix_add_report(bulletin:bulletin, kb:'5004305', report);
  }

  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);

  var port = kb_smb_transport();

  hotfix_security_hole();
  hotfix_check_fversion_end();
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}

