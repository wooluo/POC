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
  script_id(122128);
  script_version("1.8");
  script_cvs_date("Date: 2019/06/07 11:56:58");

  script_cve_id(
    "CVE-2019-0669"
  );
  script_bugtraq_id(106897);
  script_xref(name:"MSKB", value:"4462186");
  script_xref(name:"MSKB", value:"4461597");
  script_xref(name:"MSKB", value:"4462115");
  script_xref(name:"MSFT", value:"MS19-4462186");
  script_xref(name:"MSFT", value:"MS19-4461597");
  script_xref(name:"MSFT", value:"MS19-4462115");

  script_name(english:"Security Updates for Microsoft Excel Products (February 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Excel Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Excel Products are missing security updates. They are,
therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists when Microsoft
    Excel improperly discloses the contents of its memory. An
    attacker who exploited the vulnerability could use the
    information to compromise the user's computer or data. To exploit
    the vulnerability, an attacker could craft a special document
    file and then convince the user to open it. An attacker must know
    the memory address location where the object was created.
    (CVE-2019-0669)");
  # https://support.microsoft.com/en-ca/help/4462186/description-of-the-security-update-for-excel-2010-february-12-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-ca/help/4461597/description-of-the-security-update-for-excel-2013-february-12-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-ca/help/4462115/description-of-the-security-update-for-excel-2016-february-12-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office365-proplus-by-date
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.office.com/en-us/article/install-office-updates-2ab296f3-7f03-43a2-8e50-46de917611c5
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4462186
  -KB4461597
  -KB4462115

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0669");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl","microsoft_office_compatibility_pack_installed.nbin","smb_hotfixes.nasl","ms_bulletin_checks_possible.nasl");
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

bulletin = "MS19-02";
kbs = make_list(
'4462186',
'4461597',
'4462115'
);

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

port = kb_smb_transport();

checks = make_array(
  "14.0", make_array("sp", 2, "version", "14.0.7229.5000", "kb", "4462186"),
  "15.0", make_array("sp", 1, "version", "15.0.5111.1000", "kb", "4461597"),
  "16.0", make_nested_list(
    make_array("sp", 0, "version", "16.0.4810.1000", "channel", "MSI", "kb", "4462115"),
    # C2R
    make_array("sp", 0, "version", "16.0.8431.2372", "channel", "Deferred"),
    make_array("sp", 0, "version", "16.0.9126.2356", "channel", "Deferred", "channel_version", "1803"),
    make_array("sp", 0, "version", "16.0.10730.20280", "channel", "Deferred", "channel_version", "1808"),
    make_array("sp", 0, "version", "16.0.10730.20280", "channel", "First Release for Deferred"),
    make_array("sp", 0, "version", "16.0.11231.20164", "channel", "Current"),
    # 2019
    make_array("sp", 0, "version", "16.0.11231.20164", "channel", "2019 Retail"),
    make_array("sp", 0, "version", "16.0.10341.20010", "channel", "2019 Volume")
  )
);

if (hotfix_check_office_product(product:"Excel", checks:checks, bulletin:bulletin))
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
