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
  script_id(142687);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/12");

  script_cve_id(
    "CVE-2020-1599",
    "CVE-2020-16997",
    "CVE-2020-17000",
    "CVE-2020-17001",
    "CVE-2020-17004",
    "CVE-2020-17011",
    "CVE-2020-17014",
    "CVE-2020-17024",
    "CVE-2020-17029",
    "CVE-2020-17036",
    "CVE-2020-17038",
    "CVE-2020-17041",
    "CVE-2020-17042",
    "CVE-2020-17043",
    "CVE-2020-17044",
    "CVE-2020-17045",
    "CVE-2020-17047",
    "CVE-2020-17049",
    "CVE-2020-17051",
    "CVE-2020-17052",
    "CVE-2020-17056",
    "CVE-2020-17068",
    "CVE-2020-17069",
    "CVE-2020-17087",
    "CVE-2020-17088"
  );
  script_xref(name:"MSKB", value:"4586808");
  script_xref(name:"MSKB", value:"4586834");
  script_xref(name:"MSFT", value:"MS20-4586808");
  script_xref(name:"MSFT", value:"MS20-4586834");

  script_name(english:"KB4586808: Windows Server 2012 November 2020 Security Update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Windows installation on the remote host is missing security update 4586781. It is, therefore,
 affected by multiple vulnerabilities. Please review the vendor advisory for more details.");
  # https://support.microsoft.com/en-us/help/4586808/windows-server-2012-update
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0d6d9b2");
  # https://support.microsoft.com/en-us/help/4586834/windows-server-2012-update
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82b0555c");
  script_set_attribute(attribute:"solution", value:
"Apply Security Only update KB4586808 or Cumulative Update KB4586834.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17051");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

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

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS20-11";
kbs = make_list('4586808', '4586834');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

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
                   rollup_date:"11_2020",
                   bulletin:bulletin,
                   rollup_kb_list:[4586808, 4586834])
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
