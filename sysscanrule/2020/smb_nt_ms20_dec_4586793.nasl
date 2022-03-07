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
  script_id(143561);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/11");

  script_cve_id(
    "CVE-2020-16958",
    "CVE-2020-16959",
    "CVE-2020-16960",
    "CVE-2020-16961",
    "CVE-2020-16962",
    "CVE-2020-16963",
    "CVE-2020-16964",
    "CVE-2020-16996",
    "CVE-2020-17092",
    "CVE-2020-17094",
    "CVE-2020-17095",
    "CVE-2020-17096",
    "CVE-2020-17097",
    "CVE-2020-17098",
    "CVE-2020-17099",
    "CVE-2020-17103",
    "CVE-2020-17134",
    "CVE-2020-17136",
    "CVE-2020-17139",
    "CVE-2020-17140"
  );
  script_xref(name:"MSKB", value:"4586793");
  script_xref(name:"MSKB", value:"4592440");
  script_xref(name:"MSFT", value:"MS20-4586793");
  script_xref(name:"MSFT", value:"MS20-4592440");
  script_xref(name:"IAVA", value:"2020-A-0561");
  script_xref(name:"IAVA", value:"2020-A-0562");

  script_name(english:"KB4586793: Windows 10 Version 1809 and Windows Server 2019 December 2020 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4586793
or 4592440. It is, therefore, affected by multiple
vulnerabilities :

  - An elevation of privilege vulnerability. An attacker can
    exploit this to gain elevated privileges.
    (CVE-2020-16958, CVE-2020-16959, CVE-2020-16960,
    CVE-2020-16961, CVE-2020-16962, CVE-2020-16963,
    CVE-2020-16964, CVE-2020-17092, CVE-2020-17097,
    CVE-2020-17103, CVE-2020-17134, CVE-2020-17136)

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2020-17095,
    CVE-2020-17096)

  - An information disclosure vulnerability. An attacker can
    exploit this to disclose potentially sensitive
    information. (CVE-2020-17094, CVE-2020-17098,
    CVE-2020-17140)

  - A security feature bypass vulnerability exists. An
    attacker can exploit this and bypass the security
    feature and perform unauthorized actions compromising
    the integrity of the system/application.
    (CVE-2020-16996, CVE-2020-17099, CVE-2020-17139)");
  # https://support.microsoft.com/en-us/help/4586793/windows-10-update-kb4586793
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?92d059c3");
  # https://support.microsoft.com/en-us/help/4592440/windows-10-update-kb4592440
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1972925b");
  script_set_attribute(attribute:"solution", value:
"Apply Cumulative Update KB4586793.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS20-12";
kbs = make_list('4586793', '4592440');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"10",
                   sp:0,
                   os_build:"17763",
                   rollup_date:"12_2020",
                   bulletin:bulletin,
                   rollup_kb_list:[4586793, 4592440])
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
