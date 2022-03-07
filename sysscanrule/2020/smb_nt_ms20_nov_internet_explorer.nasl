#
# 
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(142691);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/12");

  script_cve_id("CVE-2020-17052");
  script_xref(name:"MSKB", value:"4586827");
  script_xref(name:"MSKB", value:"4586845");
  script_xref(name:"MSKB", value:"4586768");
  script_xref(name:"MSFT", value:"MS20-4586827");
  script_xref(name:"MSFT", value:"MS20-4586845");
  script_xref(name:"MSFT", value:"MS20-4586768");

  script_name(english:"Security Updates for Internet Explorer (November 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Internet Explorer installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Internet Explorer installation on the remote host is
missing a security update. It is, therefore, affected by the
following vulnerability :

  -  A remote code execution vulnerability exists in the way
     that Microsoft browsers access objects in memory. The
     vulnerability could corrupt memory in a way that could
     allow an attacker to execute arbitrary code in the
     context of the current user. An attacker who
     successfully exploited the vulnerability could gain the
     same user rights as the current user. (CVE-2020-17052)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4586827/windows-7-update");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/4586845/windows-8-1-update");
  # https://support.microsoft.com/en-us/help/4586834/windows-server-2012-update
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82b0555c");
  # https://support.microsoft.com/en-us/help/4586768/cumulative-security-update-for-internet-explorer
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f87d3078");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4586827
  -KB4586845
  -KB4586768
  -KB4586834");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS20-11';
kbs = make_list(
  '4586768',
  '4586845',
  '4586834',
  '4586827'
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
os = get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win7:'1', win8:'0',  win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname)
 audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8.1 / Windows Server 2012 R2
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.19867", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4586768") ||

  # Windows Server 2012
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"11.0.9600.19867", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4586768") ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.19867", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"4586768")
)
{
  report =  '\nNote: The fix for this issue is available in either of the following updates:\n';
  report += '  - KB4586768 : Cumulative Security Update for Internet Explorer\n';

  if(os == "6.3")
  {
    report += '  - KB4586845 : Windows 8.1 / Server 2012 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS20-11', kb:'4586845', report);
  }
  else if(os == "6.2")
  {
    report += '  - KB4586834 : Windows Server 2012 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS20-11', kb:'4586834', report);
  }
  else if(os == "6.1")
  {
    report += '  - KB4586827 : Windows 7 / Server 2008 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS20-11', kb:'4586827', report);
  }

  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);

  port = kb_smb_transport();
  replace_kb_item(name:'www/' + port + '/XSS', value:TRUE);

  hotfix_security_hole();
  hotfix_check_fversion_end();
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}

