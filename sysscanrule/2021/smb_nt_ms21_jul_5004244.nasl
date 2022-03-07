
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
  script_id(151588);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/16");

  script_cve_id(
    "CVE-2021-31183",
    "CVE-2021-31961",
    "CVE-2021-31979",
    "CVE-2021-33740",
    "CVE-2021-33743",
    "CVE-2021-33744",
    "CVE-2021-33745",
    "CVE-2021-33746",
    "CVE-2021-33749",
    "CVE-2021-33750",
    "CVE-2021-33751",
    "CVE-2021-33752",
    "CVE-2021-33754",
    "CVE-2021-33755",
    "CVE-2021-33756",
    "CVE-2021-33757",
    "CVE-2021-33759",
    "CVE-2021-33761",
    "CVE-2021-33763",
    "CVE-2021-33764",
    "CVE-2021-33765",
    "CVE-2021-33771",
    "CVE-2021-33773",
    "CVE-2021-33774",
    "CVE-2021-33779",
    "CVE-2021-33780",
    "CVE-2021-33781",
    "CVE-2021-33782",
    "CVE-2021-33783",
    "CVE-2021-33784",
    "CVE-2021-33785",
    "CVE-2021-33786",
    "CVE-2021-33788",
    "CVE-2021-34438",
    "CVE-2021-34440",
    "CVE-2021-34441",
    "CVE-2021-34442",
    "CVE-2021-34444",
    "CVE-2021-34445",
    "CVE-2021-34446",
    "CVE-2021-34447",
    "CVE-2021-34448",
    "CVE-2021-34449",
    "CVE-2021-34450",
    "CVE-2021-34454",
    "CVE-2021-34455",
    "CVE-2021-34456",
    "CVE-2021-34457",
    "CVE-2021-34458",
    "CVE-2021-34459",
    "CVE-2021-34460",
    "CVE-2021-34462",
    "CVE-2021-34466",
    "CVE-2021-34476",
    "CVE-2021-34488",
    "CVE-2021-34489",
    "CVE-2021-34490",
    "CVE-2021-34491",
    "CVE-2021-34492",
    "CVE-2021-34493",
    "CVE-2021-34494",
    "CVE-2021-34496",
    "CVE-2021-34497",
    "CVE-2021-34498",
    "CVE-2021-34499",
    "CVE-2021-34500",
    "CVE-2021-34503",
    "CVE-2021-34504",
    "CVE-2021-34507",
    "CVE-2021-34508",
    "CVE-2021-34509",
    "CVE-2021-34510",
    "CVE-2021-34511",
    "CVE-2021-34512",
    "CVE-2021-34514",
    "CVE-2021-34516",
    "CVE-2021-34525"
  );
  script_xref(name:"MSKB", value:"5004244");
  script_xref(name:"MSFT", value:"MS21-5004244");
  script_xref(name:"IAVA", value:"2021-A-0319");
  script_xref(name:"IAVA", value:"2021-A-0318");

  script_name(english:"KB5004244: Windows 10 version 1809 / Windows Server 2019 Security Update  Security Update (July 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 5004244. It is, therefore, affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"solution", value:
"Apply Cumulative Update 5004244");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34525");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/13");

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

bulletin = 'MS21-07';
kbs = make_list(
  '5004244'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:'10', 
                   os_build:17763,
                   rollup_date:'07_2021',
                   bulletin:bulletin,
                   rollup_kb_list:[5004244])
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
