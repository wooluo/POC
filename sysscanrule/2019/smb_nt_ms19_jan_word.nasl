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
  script_id(121028);
  script_version("1.6");
  script_cvs_date("Date: 2019/06/13 17:57:55");

  script_cve_id(
    "CVE-2019-0561",
    "CVE-2019-0585"
  );
  script_xref(name:"MSKB", value:"4461543");
  script_xref(name:"MSKB", value:"4461594");
  script_xref(name:"MSKB", value:"4461625");
  script_xref(name:"MSFT", value:"MS19-4461543");
  script_xref(name:"MSFT", value:"MS19-4461594");
  script_xref(name:"MSFT", value:"MS19-4461625");

  script_name(english:"Security Updates for Microsoft Word Products (January 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Word Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Word Products are missing security updates. It
is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft Word software when it fails to properly handle
    objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user.  (CVE-2019-0585)

  - An information disclosure vulnerability exists when
    Microsoft Word macro buttons are used improperly. An
    attacker who successfully exploited this vulnerability
    could read arbitrary files from a targeted system.
    (CVE-2019-0561)");
  # https://support.microsoft.com/en-us/help/4461543/description-of-the-security-update-for-word-2016-january-8-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4461594/description-of-the-security-update-for-word-2013-january-8-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4461625/description-of-the-security-update-for-word-2010-january-8-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office365-proplus-by-date
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.office.com/en-us/article/install-office-updates-2ab296f3-7f03-43a2-8e50-46de917611c5
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4461543
  -KB4461594
  -KB4461625

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0585");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl","smb_hotfixes.nasl","ms_bulletin_checks_possible.nasl");
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

bulletin = "MS19-01";
kbs = make_list(
'4461543',
'4461594',
'4461625'
);

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

port = kb_smb_transport();

checks = make_array(
  "14.0", make_array("sp", 2, "version", "14.0.7228.5000", "kb", "4461625"),
  "15.0", make_array("sp", 1, "version", "15.0.5101.1001", "kb", "4461594"),
  "16.0", make_nested_list(
    make_array("sp", 0, "version", "16.0.4795.1001", "channel", "MSI", "kb", "4461543"),
    # C2R
    make_array("sp", 0, "version", "16.0.8431.2366", "channel", "Deferred"),
    make_array("sp", 0, "version", "16.0.9126.2351", "channel", "Deferred", "channel_version", "1803"),
    make_array("sp", 0, "version", "16.0.10730.20264", "channel", "Deferred", "channel_version", "1808"),
    make_array("sp", 0, "version", "16.0.10730.20264", "channel", "First Release for Deferred"),
    make_array("sp", 0, "version", "16.0.11126.20192", "channel", "Current"),
    # 2019
    make_array("sp", 0, "version", "16.0.11126.20192", "channel", "2019 Retail"),
    make_array("sp", 0, "version", "16.0.10340.20017", "channel", "2019 Volume")
  )
);

if (hotfix_check_office_product(product:"Word", checks:checks, bulletin:bulletin))
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
