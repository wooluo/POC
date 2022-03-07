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
  script_id(149392);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/12");

  script_cve_id(
    "CVE-2020-24587",
    "CVE-2020-24588",
    "CVE-2020-26144",
    "CVE-2021-26419",
    "CVE-2021-28455",
    "CVE-2021-28476",
    "CVE-2021-31182",
    "CVE-2021-31184",
    "CVE-2021-31186",
    "CVE-2021-31188",
    "CVE-2021-31193",
    "CVE-2021-31194"
  );
  script_xref(name:"MSKB", value:"5003228");
  script_xref(name:"MSKB", value:"5003233");
  script_xref(name:"MSFT", value:"MS21-5003228");
  script_xref(name:"MSFT", value:"MS21-5003233");

  script_name(english:"KB5003233: Windows 7 SP2 and Windows Server 2008 R2 (Monthly Rollup) May 2021 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security updates. It is, therefore, affected by multiple vulnerabilities: Note that
Nessus has not tested for this issue but has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5003228");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5003233");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
- KB5003228
- KB5003233");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28476");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
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

bulletin = 'MS21-05';
kbs = make_list(
  '5003233',
  '5003228'
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
                   rollup_date:'05_2021',
                   bulletin:bulletin,
                   rollup_kb_list:[5003233, 5003228])
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