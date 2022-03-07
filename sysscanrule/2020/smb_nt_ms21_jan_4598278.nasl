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
  script_id(144881);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id(
    "CVE-2021-1648",
    "CVE-2021-1649",
    "CVE-2021-1650",
    "CVE-2021-1652",
    "CVE-2021-1653",
    "CVE-2021-1654",
    "CVE-2021-1655",
    "CVE-2021-1656",
    "CVE-2021-1657",
    "CVE-2021-1658",
    "CVE-2021-1659",
    "CVE-2021-1660",
    "CVE-2021-1661",
    "CVE-2021-1664",
    "CVE-2021-1665",
    "CVE-2021-1666",
    "CVE-2021-1667",
    "CVE-2021-1668",
    "CVE-2021-1671",
    "CVE-2021-1673",
    "CVE-2021-1674",
    "CVE-2021-1676",
    "CVE-2021-1678",
    "CVE-2021-1679",
    "CVE-2021-1688",
    "CVE-2021-1693",
    "CVE-2021-1694",
    "CVE-2021-1695",
    "CVE-2021-1696",
    "CVE-2021-1699",
    "CVE-2021-1700",
    "CVE-2021-1701",
    "CVE-2021-1702",
    "CVE-2021-1704",
    "CVE-2021-1706",
    "CVE-2021-1708",
    "CVE-2021-1709",
    "CVE-2021-1710"
  );
  script_xref(name:"MSKB", value:"4598278");
  script_xref(name:"MSKB", value:"4598297");
  script_xref(name:"MSFT", value:"MS21-4598278");
  script_xref(name:"MSFT", value:"MS21-4598297");

  script_name(english:"KB4598297: Windows Server 2012 January 2021 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update 4598297
or cumulative update 4598278. It is, therefore, affected by
multiple vulnerabilities :

  - An elevation of privilege vulnerability. An attacker can
    exploit this to gain elevated privileges.
    (CVE-2021-1648, CVE-2021-1649, CVE-2021-1650,
    CVE-2021-1652, CVE-2021-1653, CVE-2021-1654,
    CVE-2021-1655, CVE-2021-1659, CVE-2021-1661,
    CVE-2021-1688, CVE-2021-1693, CVE-2021-1694,
    CVE-2021-1695, CVE-2021-1702, CVE-2021-1704,
    CVE-2021-1706, CVE-2021-1709)

  - A denial of service (DoS) vulnerability. An attacker can
    exploit this issue to cause the affected component to
    deny system or application services. (CVE-2021-1679)

  - A security feature bypass vulnerability exists. An
    attacker can exploit this and bypass the security
    feature and perform unauthorized actions compromising
    the integrity of the system/application. (CVE-2021-1674,
    CVE-2021-1678)

  - An information disclosure vulnerability. An attacker can
    exploit this to disclose potentially sensitive
    information. (CVE-2021-1656, CVE-2021-1676,
    CVE-2021-1696, CVE-2021-1699, CVE-2021-1708)

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2021-1657,
    CVE-2021-1658, CVE-2021-1660, CVE-2021-1664,
    CVE-2021-1665, CVE-2021-1666, CVE-2021-1667,
    CVE-2021-1668, CVE-2021-1671, CVE-2021-1673,
    CVE-2021-1700, CVE-2021-1701, CVE-2021-1710)");
  # https://support.microsoft.com/en-us/help/4598278/windows-server-2012-update
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bbb76f59");
  # https://support.microsoft.com/en-us/help/4598297/windows-server-2012-update
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b71d9485");
  script_set_attribute(attribute:"solution", value:
"Apply Security Only update KB4598297 or Cumulative Update KB4598278.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1657");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/12");

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

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS21-01";
kbs = make_list('4598278', '4598297'); # changed by manual execution of PT scriptsautomation

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Windows 8 EOL
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  smb_check_rollup(os:"6.2",
                   sp:0,
                   rollup_date:"01_2021",
                   bulletin:bulletin,
                   rollup_kb_list:[4598297, 4598278])
)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}
