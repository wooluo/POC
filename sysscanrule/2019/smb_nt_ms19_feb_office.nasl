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
  script_id(122132);
  script_version("1.8");
  script_cvs_date("Date: 2019/06/07 11:56:58");

  script_cve_id(
    "CVE-2019-0538",
    "CVE-2019-0540",
    "CVE-2019-0582",
    "CVE-2019-0669",
    "CVE-2019-0671",
    "CVE-2019-0672",
    "CVE-2019-0673",
    "CVE-2019-0674",
    "CVE-2019-0675"
  );
  script_bugtraq_id(
    106419,
    106433
  );
  script_xref(name:"MSKB", value:"4018294");
  script_xref(name:"MSKB", value:"4018300");
  script_xref(name:"MSKB", value:"4018313");
  script_xref(name:"MSKB", value:"4462138");
  script_xref(name:"MSKB", value:"4462146");
  script_xref(name:"MSKB", value:"4462174");
  script_xref(name:"MSKB", value:"4462177");
  script_xref(name:"MSFT", value:"MS19-4018294");
  script_xref(name:"MSFT", value:"MS19-4018300");
  script_xref(name:"MSFT", value:"MS19-4018313");
  script_xref(name:"MSFT", value:"MS19-4462138");
  script_xref(name:"MSFT", value:"MS19-4462146");
  script_xref(name:"MSFT", value:"MS19-4462174");
  script_xref(name:"MSFT", value:"MS19-4462177");

  script_name(english:"Security Updates for Microsoft Office Products (February 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates. They
are, therefore, affected by multiple vulnerabilities:

  - A remote code execution vulnerability exists when the Windows Jet
    Database Engine improperly handles objects in memory. An attacker
    who successfully exploited this vulnerability could execute
    arbitrary code on a victim system. An attacker could exploit this
    vulnerability by enticing a victim to open a specially crafted
    file. (CVE-2019-0538, CVE-2019-0582)

  - A security feature bypass vulnerability exists when Microsoft
    Office does not validate URLs. An attacker could send a victim a
    specially crafted file, which could trick the victim into
    entering credentials. An attacker who successfully exploited this
    vulnerability could perform a phishing attack. (CVE-2019-0540)

  - An information disclosure vulnerability exists when Microsoft
    Excel improperly discloses the contents of its memory. An
    attacker who exploited the vulnerability could use the
    information to compromise the user's computer or data. To exploit
    the vulnerability, an attacker could craft a special document
    file and then convince the user to open it. An attacker must know
    the memory address location where the object was created.
    (CVE-2019-0669)

  - A remote code execution vulnerability exists when the Microsoft
    Office Access Connectivity Engine improperly handles objects in
    memory. An attacker who successfully exploited this vulnerability
    could execute arbitrary code on a victim system. An attacker
    could exploit this vulnerability by enticing a victim to open a
    specially crafted file. (CVE-2019-0671,  CVE-2019-0672, 
    CVE-2019-0673,  CVE-2019-0674, CVE-2019-0675)");
  # https://support.microsoft.com/en-ca/help/4018313/description-of-the-security-update-for-office-2010-february-12-2019 
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-ca/help/4462177/description-of-the-security-update-for-office-2010-february-12-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-ca/help/4462174/description-of-the-security-update-for-office-2010-february-12-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-ca/help/4462138/description-of-the-security-update-for-office-2013-february-12-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-ca/help/4018300/description-of-the-security-update-for-office-2013-february-12-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-ca/help/4462146/description-of-the-security-update-for-office-2016-february-12-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-ca/help/4018294/description-of-the-security-update-for-office-2016-february-12-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office365-proplus-by-date
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.office.com/en-us/article/install-office-updates-2ab296f3-7f03-43a2-8e50-46de917611c5
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB4018294
  -KB4018300
  -KB4018313
  -KB4462138
  -KB4462146
  -KB4462174
  -KB4462177

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0538");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
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
include("misc_func.inc");
include("install_func.inc");

global_var vuln;

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS19-02";
kbs = make_list(
  '4018294', # Office 2016
  '4018300', # Office 2013 SP1
  '4018313', # Office 2010 SP2
  '4462138', # Office 2013 SP1
  '4462146', # Office 2016
  '4462174', # Office 2010 SP2
  '4462177'  # Office 2010 SP2
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

office_vers = hotfix_check_office_version();

# Office 2010 SP2
if (office_vers["14.0"])
{
  office_sp = get_kb_item("SMB/Office/2010/SP");
  if (!isnull(office_sp) && office_sp == 2)
  {
    prod = "Microsoft Office 2010 SP2";

    path = hotfix_get_officecommonfilesdir(officever:"14.0");
    path = hotfix_append_path(path:path, value:"Microsoft Shared\Office14");
    kb = "4462174";
    file = "mso.dll";
    version = "14.0.7229.5000";
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officeprogramfilesdir(officever:"14.0");
    path = hotfix_append_path(path:path, value:"Microsoft Office\Office14");
    kb = "4462177";
    file = "graph.exe";
    version = "14.0.7229.5000";
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;


    path = hotfix_get_officecommonfilesdir(officever:"14.0");
    path = hotfix_append_path(path:path, value:"Microsoft Shared\Office14");
    kb = "4018313";
    file = "acecore.dll";
    version = "14.0.7229.5000";
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
  }
}

# Office 2013 SP1
if (office_vers["15.0"])
{
  office_sp = get_kb_item("SMB/Office/2013/SP");
  if (!isnull(office_sp) && office_sp == 1)
  {
    prod = "Microsoft Office 2013 SP1";

    path = hotfix_get_officecommonfilesdir(officever:"15.0");
    path = hotfix_append_path(path:path, value:"Microsoft Shared\Office15");
    kb = "4462138";
    file = "mso.dll";
    version = "15.0.5111.1000";
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officecommonfilesdir(officever:"15.0");
    path = hotfix_append_path(path:path, value:"Microsoft Shared\Office15");
    kb = "4018300";
    file = "acecore.dll";
    version = "15.0.5111.1000";
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
  }
}

# Office 2016
if (office_vers["16.0"])
{
  office_sp = get_kb_item("SMB/Office/2016/SP");
  if (!isnull(office_sp) && office_sp == 0)
  {
    prod = "Microsoft Office 2016";
    prod2019 = "Microsoft Office 2019";

    path = hotfix_get_officecommonfilesdir(officever:"16.0");
    mso_dll_path = hotfix_append_path(path:path, value:"Microsoft Shared\Office16");

    path = hotfix_get_officecommonfilesdir(officever:"16.0");
    acecore_dll_path = hotfix_append_path(path:path, value:"Microsoft Shared\Office16");

    c2r_path = mso_dll_path;

    # MSI acecore.dll
    if (hotfix_check_fversion(file:"acecore.dll", version:"16.0.4810.1000", channel:"MSI", channel_product:"Office", path:acecore_dll_path, kb:"4018294", bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    if (
      # MSI mso.dll
      hotfix_check_fversion(file:"mso.dll", version:"16.0.4810.1000", channel:"MSI", channel_product:"Office", path:mso_dll_path, kb:"4462146", bulletin:bulletin, product:prod) == HCF_OLDER ||
      # C2R
      hotfix_check_fversion(file:"mso.dll", version:"16.0.8431.2372", channel:"Deferred", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:"mso.dll", version:"16.0.9126.2356", channel:"Deferred", channel_version:"1803", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:"mso.dll", version:"16.0.10730.20280", channel:"Deferred", channel_version:"1808", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:"mso.dll", version:"16.0.10730.20280", channel:"First Release for Deferred", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:"mso.dll", version:"16.0.11231.20164", channel:"Current", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      # 2019
      hotfix_check_fversion(file:"mso.dll", version:"16.0.11231.20164", channel:"2019 Retail", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod2019) == HCF_OLDER ||
      hotfix_check_fversion(file:"mso.dll", version:"16.0.10341.20010", channel:"2019 Volume", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod2019) == HCF_OLDER
    )
    vuln = TRUE;
  }
}

if (vuln)
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
