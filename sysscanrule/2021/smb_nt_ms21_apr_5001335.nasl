##
# 
#
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
##

include('compat.inc');

if (description)
{
  script_id(148466);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/22");

  script_cve_id(
    "CVE-2021-26413",
    "CVE-2021-26415",
    "CVE-2021-27089",
    "CVE-2021-27091",
    "CVE-2021-27093",
    "CVE-2021-27095",
    "CVE-2021-27096",
    "CVE-2021-28309",
    "CVE-2021-28315",
    "CVE-2021-28316",
    "CVE-2021-28317",
    "CVE-2021-28318",
    "CVE-2021-28323",
    "CVE-2021-28327",
    "CVE-2021-28328",
    "CVE-2021-28329",
    "CVE-2021-28330",
    "CVE-2021-28331",
    "CVE-2021-28332",
    "CVE-2021-28333",
    "CVE-2021-28334",
    "CVE-2021-28335",
    "CVE-2021-28336",
    "CVE-2021-28337",
    "CVE-2021-28338",
    "CVE-2021-28339",
    "CVE-2021-28340",
    "CVE-2021-28341",
    "CVE-2021-28342",
    "CVE-2021-28343",
    "CVE-2021-28344",
    "CVE-2021-28345",
    "CVE-2021-28346",
    "CVE-2021-28348",
    "CVE-2021-28349",
    "CVE-2021-28350",
    "CVE-2021-28352",
    "CVE-2021-28353",
    "CVE-2021-28354",
    "CVE-2021-28355",
    "CVE-2021-28356",
    "CVE-2021-28357",
    "CVE-2021-28358",
    "CVE-2021-28434",
    "CVE-2021-28437",
    "CVE-2021-28439",
    "CVE-2021-28440",
    "CVE-2021-28443",
    "CVE-2021-28445",
    "CVE-2021-28446"
  );
  script_xref(name:"MSKB", value:"5001335");
  script_xref(name:"MSKB", value:"5001392");
  script_xref(name:"MSFT", value:"MS21-5001335");
  script_xref(name:"MSFT", value:"MS21-5001392");
  script_xref(name:"IAVA", value:"2021-A-0171");

  script_name(english:"KB5001335: Windows Server 2008 R2 Apr 2021 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security updates. It is, therefore, affected by multiple vulnerabilities:

  - Microsoft Internet Messaging API Remote Code Execution Vulnerability (CVE-2021-27089)

  - RPC Endpoint Mapper Service Elevation of Privilege Vulnerability (CVE-2021-27091)

  - Windows Kernel Information Disclosure Vulnerability (CVE-2021-27093, CVE-2021-28309)

  - Windows Media Video Decoder Remote Code Execution Vulnerability (CVE-2021-27095, CVE-2021-28315)

  - NTFS Elevation of Privilege Vulnerability (CVE-2021-27096)

  - Windows Installer Spoofing Vulnerability (CVE-2021-26413)

  - Windows Installer Elevation of Privilege Vulnerability (CVE-2021-26415, CVE-2021-28440)

  - Windows WLAN AutoConfig Service Security Feature Bypass Vulnerability (CVE-2021-28316)

  - Microsoft Windows Codecs Library Information Disclosure Vulnerability (CVE-2021-28317)

  - Windows GDI+ Information Disclosure Vulnerability (CVE-2021-28318)

  - Windows DNS Information Disclosure Vulnerability (CVE-2021-28323, CVE-2021-28328)

  - Remote Procedure Call Runtime Remote Code Execution Vulnerability (CVE-2021-28327, CVE-2021-28329,
    CVE-2021-28330, CVE-2021-28331, CVE-2021-28332, CVE-2021-28333, CVE-2021-28334, CVE-2021-28335,
    CVE-2021-28336, CVE-2021-28337, CVE-2021-28338, CVE-2021-28339, CVE-2021-28340, CVE-2021-28341,
    CVE-2021-28342, CVE-2021-28343, CVE-2021-28344, CVE-2021-28345, CVE-2021-28346, CVE-2021-28352,
    CVE-2021-28353, CVE-2021-28354, CVE-2021-28355, CVE-2021-28356, CVE-2021-28357, CVE-2021-28358,
    CVE-2021-28434)

  - Windows GDI+ Remote Code Execution Vulnerability (CVE-2021-28348, CVE-2021-28349, CVE-2021-28350)

  - Windows Installer Information Disclosure Vulnerability (CVE-2021-28437)

  - Windows TCP/IP Driver Denial of Service Vulnerability (CVE-2021-28439)

  - Windows Console Driver Denial of Service Vulnerability (CVE-2021-28443)

  - N/A (CVE-2021-28445, CVE-2021-28446)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5001335");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5001392");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
- KB5001335
- KB5001392");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21199");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS21-04';
kbs = make_list(
  '5001335',
  '5001392'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win7:'1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'6.1', 
                   sp:1,
                   rollup_date:'04_2021',
                   bulletin:bulletin,
                   rollup_kb_list:[5001335, 5001392])
)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
