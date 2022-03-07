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
  script_id(126585);
  script_version("1.4");
  script_cvs_date("Date: 2019/08/16 15:34:48");

  script_cve_id("CVE-2019-1084");
  script_bugtraq_id(108929);

  script_xref(name:"MSKB", value:"4464592");
  script_xref(name:"MSKB", value:"4475509");
  script_xref(name:"MSKB", value:"4475517");
  script_xref(name:"MSFT", value:"MS19-4464592");
  script_xref(name:"MSFT", value:"MS19-4475509");
  script_xref(name:"MSFT", value:"MS19-4475517");

  script_name(english:"Security Updates for Outlook (July 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Outlook application installed on the remote host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Outlook application installed on the remote host is missing security updates. It is, therefore, affected
by a vulnerability:

  - An information disclosure vulnerability exists when Exchange allows creation of entities with Display Names having
    non-printable characters. An authenticated attacker could exploit this vulnerability by creating entities with
    invalid display names, which, when added to conversations, remain invisible. (CVE-2019-1084)");
  # https://support.microsoft.com/en-us/help/4475517/security-update-for-outlook-2016-july-9-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4475509/security-update-for-outlook-2010-july-9-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4464592/security-update-for-outlook-2013-july-9-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office365-proplus-by-date
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.office.com/en-us/article/install-office-updates-2ab296f3-7f03-43a2-8e50-46de917611c5
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB4464592
  -KB4475517
  -KB4475509

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1084");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl","ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("install_func.inc");

global_var vuln;

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS19-07";
kbs = make_list(
  4475509,
  4464592,
  4475517
);

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

port = kb_smb_transport();

checks = make_array(
  "14.0", make_array("sp", 2, "version", "14.0.7235.5000", "kb", "4475509"),
  "15.0", make_array("sp", 1, "version", "15.0.5153.1000", "kb", "4464592"),
  "16.0", make_nested_list(make_array("sp", 0, "version", "16.0.4873.1000", "channel", "MSI", "kb", "4475517"),
    # C2R
    make_array("version", "16.0.9126.2428", "channel", "Deferred"),
    make_array("version", "16.0.10730.20360", "channel", "Deferred", "channel_version", "1808"),
    make_array("version", "16.0.11328.20368", "channel", "Deferred", "channel_version", "1902"),
    make_array("version", "16.0.11328.20368", "channel", "First Release for Deferred"),
    make_array("version", "16.0.11727.20244", "channel", "Current"),
    # 2019
    make_array("version", "16.0.11727.20244", "channel", "2019 Retail"),
    make_array("version", "16.0.10348.20020", "channel", "2019 Volume"))
);

if (hotfix_check_office_product(product:"Outlook", checks:checks, bulletin:bulletin))
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
