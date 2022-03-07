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
  script_id(122859);
  script_version("1.1");
  script_cvs_date("Date: 2019/03/14 15:35:21");

  script_cve_id("CVE-2019-0778", "CVE-2019-0604");
  script_bugtraq_id(
    106914,
    107226
  );
  script_xref(name:"MSKB", value:"4462184");
  script_xref(name:"MSKB", value:"4462199");
  script_xref(name:"MSKB", value:"4462202");
  script_xref(name:"MSKB", value:"4462208");
  script_xref(name:"MSKB", value:"4462211");
  script_xref(name:"MSKB", value:"4462217");
  script_xref(name:"MSKB", value:"4462219");
  script_xref(name:"MSKB", value:"4462228");

  script_xref(name:"MSFT", value:"MS19-4462184");
  script_xref(name:"MSFT", value:"MS19-4462199");
  script_xref(name:"MSFT", value:"MS19-4462202");
  script_xref(name:"MSFT", value:"MS19-4462208");
  script_xref(name:"MSFT", value:"MS19-4462211");
  script_xref(name:"MSFT", value:"MS19-4462217");
  script_xref(name:"MSFT", value:"MS19-4462219");
  script_xref(name:"MSFT", value:"MS19-4462228");

  script_name(english:"Security Updates for Microsoft Sharepoint Server (March 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Sharepoint Server installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Sharepoint Server installation on the remote
host is missing a security update. It is, therefore,
affected by the following vulnerabilities:

  - A cross-site-scripting (XSS) vulnerability exists when
    Microsoft SharePoint Server does not properly sanitize a
    specially crafted web request to an affected SharePoint
    server. An authenticated attacker could exploit the
    vulnerability by sending a specially crafted request to
    an affected SharePoint server. The attacker who
    successfully exploited the vulnerability could then
    perform cross-site scripting attacks on affected systems
    and run script in the security context of the current
    user. The attacks could allow the attacker to read
    content that the attacker is not authorized to read, use
    the victim's identity to take actions on the SharePoint
    site on behalf of the user, such as change permissions
    and delete content, and inject malicious content in the
    browser of the user. The security update addresses the
    vulnerability by helping to ensure that SharePoint
    Server properly sanitizes web requests. (CVE-2019-0778)

  - A remote code execution vulnerability exists in Microsoft
    SharePoint when the software fails to check the source markup of
    an application package. An attacker who successfully exploited
    the vulnerability could run arbitrary code in the context of the
    SharePoint application pool and the SharePoint server farm
    account. Exploitation of this vulnerability requires that a user
    uploads a specially crafted SharePoint application package to an
    affected versions of SharePoint.(CVE-2019-0604)

");
  # https://support.microsoft.com/en-us/help/4462184/description-of-the-security-update-for-sharepoint-server-2010-march-12
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4462202/description-of-the-security-update-for-sharepoint-enterprise-server
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4462208/description-of-the-security-update-for-sharepoint-foundation-2013
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4462211/description-of-the-security-update-for-sharepoint-enterprise-server
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4462199/description-of-the-security-update-for-sharepoint-server-2019-march-12
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4462184
  -KB4462199
  -KB4462202
  -KB4462208
  -KB4462211
");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0604");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_sharepoint_installed.nbin","smb_hotfixes.nasl","ms_bulletin_checks_possible.nasl");
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

bulletin = "MS19-03";
kbs = make_list(
  '4462184', # 2010
  '4462202', # 2013
  '4462208', # 2013
  '4462211', # 2016
  '4462199'  # 2019
);

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, "Failed to determine the location of %windir%.");

registry_init();

var sps_2010_path, sps_2010_sp, sps_2010_edition;
var sps_2013_path, sps_2013_sp, sps_2013_edition;
var sps_2016_path, sps_2016_sp, sps_2016_edition;
var sps_2019_path, sps_2019_sp, sps_2019_edition;

vuln = FALSE;
port = kb_smb_transport();

installs = get_installs(app_name:"Microsoft SharePoint Server", exit_if_not_found:TRUE);

foreach install (installs[1])
{
  if (install["Product"] == "2010")
  {
    sps_2010_path = install['path'];
    sps_2010_sp = install['SP'];
    sps_2010_edition = install['Edition'];
  } 
  else if (install["Product"] == "2013")
  {
    sps_2013_path = install['path'];
    sps_2013_sp = install['SP'];
    sps_2013_edition = install['Edition'];
  }
  else if (install["Product"] == "2016")
  {
    sps_2016_path = install['path'];
    sps_2016_sp = install['SP'];
    sps_2016_edition = install['Edition'];
  }
  else if (install["Product"] == "2019")
  {
    sps_2019_path = install['path'];
    sps_2019_sp = install['SP'];
    sps_2019_edition = install['Edition'];
  }
}

######################################################################
# SharePoint Enterprise Server 2010 SP1
######################################################################
if (sps_2010_path && sps_2010_sp == "2")
{
  if (sps_2010_edition == "Server")
  {
    commonfiles = hotfix_get_commonfilesdir();
    path = hotfix_append_path(path:commonfiles, value:"microsoft shared\Web Server Extensions\14\ISAPI");
    if (hotfix_check_fversion(file:"microsoft.sharepoint.portal.dll", version:"14.0.7231.5000", min_version:"14.0.0.0", path:path, kb:"4462184", product:"Microsoft SharePoint Enterprise Server 2010 SP 2") == HCF_OLDER)
      vuln = TRUE;
   
  }
}

######################################################################
# SharePoint Enterprise Server 2013 SP1
######################################################################
if (sps_2013_path && sps_2013_sp == "1")
{
  if (sps_2013_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2013_path, value:"WebServices\ConversionServices");
    if (hotfix_check_fversion(file:"msoserver.dll", version:"15.0.5119.1000", min_version:"15.0.0.0", path:path, kb:"4462202", product:"Microsoft SharePoint Enterprise Server 2013 SP 1") == HCF_OLDER)
      vuln = TRUE;
  }

  if (sps_2013_edition == "Foundation")
  {
    commonfiles = hotfix_get_commonfilesdir();
    path = hotfix_append_path(path:commonfiles, value:"microsoft shared\Web Server Extensions\15\bin");
    if (hotfix_check_fversion(file:"onetutil.dll", version:"15.0.5119.1000", min_version:"15.0.0.0", path:path, kb:"4462208", product:"Microsoft SharePoint Foundation Server 2013 SP 1") == HCF_OLDER)
      vuln = TRUE;
      xss = TRUE;
  }

}

######################################################################
# SharePoint Server 2016
######################################################################
if (sps_2016_path && sps_2016_sp == "0" && sps_2016_edition == "Server")
{
  path = hotfix_append_path(path:sps_2016_path, value:"WebServices\ConversionServices");
  if (hotfix_check_fversion(file:"sword.dll", version:"16.0.4822.1000", min_version:"16.0.0.0", path:path, kb:"4462211", product:"Microsoft SharePoint Server 2016") == HCF_OLDER)
    vuln = TRUE;
    xss = TRUE;
}

######################################################################
# SharePoint Server 2019
######################################################################

if (sps_2019_path && sps_2019_sp == "0" && sps_2019_edition == "Server")
{
  path = hotfix_append_path(path:sps_2019_path, value:"WebServices\ConversionServices");
  if (hotfix_check_fversion(file:"sword.dll", version:"16.0.10342.12113", min_version:"16.0.0.0", path:path, kb:"4462199", product:"Microsoft SharePoint Server 2019") == HCF_OLDER)
    vuln = TRUE;
}


# check for vuln and report... 
if (vuln)
{
  if (xss) replace_kb_item(name:'www/'+port+'/XSS', value:TRUE);
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
