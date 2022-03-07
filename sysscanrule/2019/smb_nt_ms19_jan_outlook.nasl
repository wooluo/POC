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
  script_id(121027);
  script_version("1.6");
  script_cvs_date("Date: 2019/07/12 12:39:17");

  script_cve_id("CVE-2019-0559");
  script_xref(name:"MSKB", value:"4461595");
  script_xref(name:"MSKB", value:"4461601");
  script_xref(name:"MSKB", value:"4461623");
  script_xref(name:"MSFT", value:"MS19-4461595");
  script_xref(name:"MSFT", value:"MS19-4461601");
  script_xref(name:"MSFT", value:"MS19-4461623");

  script_name(english:"Security Updates for Outlook (January 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Outlook application installed on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Outlook application installed on the remote
host is missing a security update. It is, therefore,
affected by the following vulnerability :

  - An information disclosure vulnerability exists when
    Microsoft Outlook improperly handles certain types of
    messages. An attacker who successfully exploited this
    vulnerability could gather information about the victim.
    An attacker could exploit this vulnerability by sending
    a specially crafted email to the victim. The update
    addresses the vulnerability by correcting the way
    Microsoft Outlook handles these types of messages.
    (CVE-2019-0559)");
  # https://support.microsoft.com/en-us/help/4461623/description-of-the-security-update-for-outlook-2010-january-8-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4461595/description-of-the-security-update-for-outlook-2013-january-8-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4461601/description-of-the-security-update-for-outlook-2016-january-8-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office365-proplus-by-date
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.office.com/en-us/article/install-office-updates-2ab296f3-7f03-43a2-8e50-46de917611c5
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4461595
  -KB4461601
  -KB4461623

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0559");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/08");

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

bulletin = "MS19-01";
kbs = make_list(
'4461595',
'4461601',
'4461623'
);

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

port = kb_smb_transport();

checks = make_array(
  "14.0", make_array("version", "14.0.7227.5000", "kb", "4461623"),
  "15.0", make_array("version", "15.0.5101.1000", "kb", "4461595"),
  "16.0", make_nested_list(
    make_array("sp", 0, "version", "16.0.4795.1000", "channel", "MSI", "kb", "4461601"),
    # C2R
    make_array("version", "16.0.8431.2366", "channel", "Deferred"),
    make_array("version", "16.0.9126.2351", "channel", "Deferred", "channel_version", "1803"),
    make_array("version", "16.0.10730.20264", "channel", "Deferred", "channel_version", "1808"),
    make_array("version", "16.0.10730.20264", "channel", "First Release for Deferred"),
    make_array("version", "16.0.11126.20192", "channel", "Current"),
    # 2019
    make_array("version", "16.0.11126.20192", "channel", "2019 Retail"),
    make_array("version", "16.0.10340.20017", "channel", "2019 Volume")
  )
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
