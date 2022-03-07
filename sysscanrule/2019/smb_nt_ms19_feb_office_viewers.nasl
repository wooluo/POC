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
  script_id(122317);
  script_version("1.1");
  script_cvs_date("Date: 2019/02/19 15:43:10");

  script_cve_id(
    "CVE-2019-0540",
    "CVE-2019-0669"
  );

  script_bugtraq_id(
    106863,
    106897
  );
  script_xref(name:"MSKB", value:"4092465");
  script_xref(name:"MSKB", value:"4461607");
  script_xref(name:"MSKB", value:"4461608");
  script_xref(name:"MSKB", value:"4462154");
  script_xref(name:"MSFT", value:"MS19-4092465");
  script_xref(name:"MSFT", value:"MS19-4461607");
  script_xref(name:"MSFT", value:"MS19-4461608");
  script_xref(name:"MSFT", value:"MS19-4462154");

  script_name(english:"Security Updates for Microsoft Office Viewers And Compatibility Products (February 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Viewers and Compatibility Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Viewers and Compatibility Products are
missing security updates. It is, therefore, affected by multiple
vulnerabilities :

  - A security feature bypass vulnerability exists when
    Microsoft Office does not validate URLs. An attacker
    could send a victim a specially crafted file, which
    could trick the victim into entering credentials. An
    attacker who successfully exploited this vulnerability
    could perform a phishing attack. The update addresses
    the vulnerability by ensuring Microsoft Office properly
    validates URLs. (CVE-2019-0540)

  - An information disclosure vulnerability exists when
    Microsoft Excel improperly discloses the contents of its
    memory. An attacker who exploited the vulnerability
    could use the information to compromise the users
    computer or data. (CVE-2019-0669)");
  # https://support.microsoft.com/en-us/help/4461608/description-of-the-security-update-for-excel-viewer-2007-february-12
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4462154/description-of-the-security-update-for-word-viewer-february-12-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4461607/description-of-the-security-update-for-microsoft-office-compatibility
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4092465/description-of-the-security-update-for-microsoft-office-viewers
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  - KB4092465
  - KB4461607
  - KB4461608
  - KB4462154");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0669");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
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
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS19-02";
kbs = make_list(
  '4092465', # Excel Viewer and PowerPoint Viewer
  '4461607', # Office Compatability Viewer
  '4461608', # Excel Viewer
  '4462154'  # Office Word Viewer
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

##
# Excel Viewer
#
#
##
function perform_excel_viewer_checks()
{
  var prod, path, install, installs, common_path;
  prod = "Microsoft Excel Viewer";
  installs = get_kb_list("SMB/Office/ExcelViewer/*/ProductPath");

  foreach install (keys(installs))
  {
    common_path = installs[install];
    path = ereg_replace(pattern:"^([A-Za-z]:.*)\\Microsoft Office.*", replace:"\1\Microsoft Office\Office12", string:common_path);

    if (
        hotfix_check_fversion(
          file:"xlview.dll",
          version:"12.0.6807.5000",
          path:path, kb:"4461608",
          bulletin:bulletin,
          product:prod
        ) == HCF_OLDER
      ) vuln = TRUE;
    if (
        hotfix_check_fversion(
          file:"mso.dll",
          version:"12.0.6807.5000",
          path:path, kb:"4092465",
          bulletin:bulletin,
          product:prod  
        ) == HCF_OLDER
      ) vuln = TRUE;
  }
}

##
# Word Viewer
#
#
##
function perform_word_viewer_checks()
{
  var install, installs, path, prod;
  prod = "Microsoft Word Viewer";

  installs = get_kb_list("SMB/Office/WordViewer/*/ProductPath");
  foreach install (keys(installs))
  {
    path = installs[install];
    path = ereg_replace(pattern:"^([A-Za-z]:.*)\\[wW]ordview.exe", replace:"\1", string:path);

    if (
        hotfix_check_fversion(
          file:"wordview.exe",
          version:"11.0.8454.0",
          path:path, kb:"4462154",
          bulletin:bulletin,
          product:prod
        ) == HCF_OLDER
      ) vuln = TRUE;
  }
}

##
# Office Compatibility Pack
#
#
##
function perform_compatibility_viewer_checks()
{
  var install, installs, path, prod;

  installs = get_kb_list("SMB/Office/ExcelCnv/*/ProductPath");
  foreach install (keys(installs))
  {
    path = installs[install];
    path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+\\.exe$', replace:"\1\", string:path, icase:TRUE);
    if (
        hotfix_check_fversion(
          path:path, file:"excelcnv.exe",
          version:"12.0.6807.5000",
          kb:"4461607",
          bulletin:bulletin,
          min_version:"12.0.0.0",
          product:"Microsoft Office Compatibility Pack"
        ) == HCF_OLDER
      )
    {
      vuln = TRUE;
      break;
    }
  }
}

######################################################################
# MAIN
######################################################################
perform_excel_viewer_checks();
perform_word_viewer_checks();
perform_compatibility_viewer_checks();

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
