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
  script_id(126583);
  script_version("1.4");
  script_cvs_date("Date: 2019/08/16 15:34:48");

  script_cve_id(
    "CVE-2019-1084",
    "CVE-2019-1109",
    "CVE-2019-1111"
  );
  script_bugtraq_id(
    108415,
    108965,
    108974
  );

  script_xref(name:"MSKB", value:"4462224");
  script_xref(name:"MSKB", value:"4464558");
  script_xref(name:"MSKB", value:"4464543");
  script_xref(name:"MSKB", value:"4018375");
  script_xref(name:"MSKB", value:"4475514");
  script_xref(name:"MSKB", value:"4464534");
  script_xref(name:"MSKB", value:"4461539");
  script_xref(name:"MSFT", value:"MS19-4462224");
  script_xref(name:"MSFT", value:"MS19-4464558");
  script_xref(name:"MSFT", value:"MS19-4464543");
  script_xref(name:"MSFT", value:"MS19-4018375");
  script_xref(name:"MSFT", value:"MS19-4475514");
  script_xref(name:"MSFT", value:"MS19-4464534");
  script_xref(name:"MSFT", value:"MS19-4461539");

  script_name(english:"Security Updates for Microsoft Office Products (July 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates. They are, therefore, affected by multiple vulnerabilities:

  - An information disclosure vulnerability exists when Exchange allows creation of entities with Display Names having
    non-printable characters. An authenticated attacker could exploit this vulnerability by creating entities with
    invalid display names, which, when added to conversations, remain invisible. (CVE-2019-1084)

  - A spoofing vulnerability exists when Microsoft Office Javascript does not check the validity of the web page making
    a request to Office documents. An attacker who successfully exploited this vulnerability could read or write
    information in Office documents. (CVE-2019-1109)

  - A remote code execution vulnerability exists in Microsoft Excel software when the software fails to properly handle
    objects in memory. An attacker who successfully exploited the vulnerability could run arbitrary code in the context
    of the current user. If the current user is logged on with administrative user rights, an attacker could take
    control of the affected system. An attacker could then install programs; view, change, or delete data; or create
    new accounts with full user rights. Users whose accounts are configured to have fewer user rights on the system
    could be less impacted than users who operate with administrative user rights. Exploitation of the vulnerability
    requires that a user open a specially crafted file with an affected version of Microsoft Excel. In an email attack
    scenario, an attacker could exploit the vulnerability by sending the specially crafted file to the user and
    convincing the user to open the file. In a web-based attack scenario, an attacker could host a website (or leverage
    a compromised website that accepts or hosts user-provided content) containing a specially crafted file designed to
    exploit the vulnerability. An attacker would have no way to force users to visit the website. Instead, an attacker
    would have to convince users to click a link, typically by way of an enticement in an email or instant message, and
    then convince them to open the specially crafted file.(CVE-2019-1111)");
  # https://support.microsoft.com/en-ca/help/4462224/security-update-for-office-2010-july-9-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-ca/help/4464558/security-update-for-office-2013-july-9-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-ca/help/4464543/security-update-for-office-2013-july-9-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-ca/help/4018375/security-update-for-office-2013-july-9-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-ca/help/4475514/security-update-for-office-2016-july-9-2019 
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-ca/help/4464534/security-update-for-office-2016-july-9-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-ca/help/4461539/security-update-for-office-2016-july-9-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office365-proplus-by-date
  script_set_attribute(attribute:"see_also", value:"");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-office-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.office.com/en-us/article/install-office-updates-2ab296f3-7f03-43a2-8e50-46de917611c5
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4462224
  -KB4464558
  -KB4464543
  -KB4018375
  -KB4475514
  -KB4464534
  -KB4461539

For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1111");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Windows : Microsoft Bulletins");

  script_dependencies("office_installed.nasl","smb_hotfixes.nasl","ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('audit.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('misc_func.inc');
include('install_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS19-07';
kbs = make_list(
  '4462224', # Office 2010 SP2
  '4464558', # Office 2013 SP1
  '4464543', # Office 2013 SP1
  '4018375', # Office 2013 SP1
  '4475514', # Office 2016
  '4464534', # Office 2016
  '4461539'  # Office 2016
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

office_vers = hotfix_check_office_version();

# Office 2010 SP2
if (office_vers['14.0'])
{
  office_sp = get_kb_item('SMB/Office/2010/SP');
  if (!isnull(office_sp) && office_sp == 2)
  {
    prod = 'Microsoft Office 2010 SP2';

    path = hotfix_get_officeprogramfilesdir(officever:"14.0");
    path = hotfix_append_path(path:path, value:"Microsoft Office\Office14");
    kb = "4462224";
    file = "graph.exe";
    version = "14.0.7235.5000";
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;
  }
}

# Office 2013 SP1
if (office_vers['15.0'])
{
  office_sp = get_kb_item('SMB/Office/2013/SP');
  if (!isnull(office_sp) && office_sp == 1)
  {
    prod = 'Microsoft Office 2013 SP1';

    path = hotfix_get_officecommonfilesdir(officever:"15.0");
    path = hotfix_append_path(path:path, value:"Microsoft Shared\Office15");
    kb = "4464558";
    file = "mso.dll";
    version = "15.0.5153.1000";
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officeprogramfilesdir(officever:"15.0");
    path = hotfix_append_path(path:path, value:"Microsoft Office\Office15");
    kb = "4464543";
    file = "graph.exe";
    version = "15.0.5153.1000";
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_get_officeprogramfilesdir(officever:"15.0");
    path = hotfix_append_path(path:path, value:"Microsoft Office\Office15");
    kb = "4018375";
    file = "osf.dll";
    version = "15.0.5153.1000";
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

    path = hotfix_get_officeprogramfilesdir(officever:"16.0");
    osf_dll_path = hotfix_append_path(path:path, value:"Microsoft Office\Office16");

    path = hotfix_get_officeprogramfilesdir(officever:"16.0");
    graph_exe_path = hotfix_append_path(path:path, value:"Microsoft Office\Office16");

    path = hotfix_get_officeprogramfilesdir(officever:"16.0");
    c2r_path = hotfix_append_path(path: path, value : "Microsoft Office\root\Office16");
    
    # MSI osf.dll
    if (hotfix_check_fversion(file:"osf.dll", version:"16.0.4873.1000", channel:"MSI", channel_product:"Office", path:osf_dll_path, kb:"4464534", bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    # MSI mso.dll
    if (hotfix_check_fversion(file:"mso.dll", version:"16.0.4873.1000", channel:"MSI", channel_product:"Office", path:mso_dll_path, kb:"4475514", bulletin:bulletin, product:prod) == HCF_OLDER)
      vuln = TRUE;

    # MSI graph.exe
    if (hotfix_check_fversion(file:"graph.exe", version:"16.0.4873.1000", channel:"MSI", channel_product:"Office", path:graph_exe_path, kb:"4461539", bulletin:bulletin, product:prod) == HCF_OLDER ||
      # C2R
      hotfix_check_fversion(file:"graph.exe", version:"16.0.9126.2428", channel:"Deferred", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:"graph.exe", version:"16.0.10730.20360", channel:"Deferred", channel_version:"1808", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:"graph.exe", version:"16.0.11328.20368", channel:"Deferred", channel_version:"1902", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:"graph.exe", version:"16.0.11328.20368", channel:"First Release for Deferred", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      hotfix_check_fversion(file:"graph.exe", version:"16.0.11727.20244", channel:"Current", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod) == HCF_OLDER ||
      # 2019
      hotfix_check_fversion(file:"graph.exe", version:"16.0.11727.20244", channel:"2019 Retail", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod2019) == HCF_OLDER ||
      hotfix_check_fversion(file:"graph.exe", version:"16.0.10348.20020", channel:"2019 Volume", channel_product:"Office", path:c2r_path, bulletin:bulletin, product:prod2019) == HCF_OLDER
    
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
