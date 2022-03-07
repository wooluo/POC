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
  script_id(127860);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/14  8:45:39");

  script_cve_id(
    "CVE-2019-1201",
    "CVE-2019-1205"
  );
  script_xref(name:"MSKB", value:"4462216");
  script_xref(name:"MSKB", value:"4475534");
  script_xref(name:"MSFT", value:"MS19-4462216");
  script_xref(name:"MSFT", value:"MS19-4475534");

  script_name(english:"Security Updates for Microsoft Office Web Apps (August 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Web Apps installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Web Apps installation on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft Word software when it fails to properly handle
    objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user.  (CVE-2019-1201,
    CVE-2019-1205)");
  # https://support.microsoft.com/en-us/help/4462216/security-update-for-office-web-apps-server-2013
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4475534/security-update-for-sharepoint-server-2010-office-web-apps
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4462216
  -KB4475534");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1201");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl","microsoft_owa_installed.nbin","microsoft_office_compatibility_pack_installed.nbin","smb_hotfixes.nasl","ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS19-08';
kbs = make_list(
  '4462216',
  '4475534'
);
if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

port = kb_smb_transport();

# Get installs of Office Web Apps
owa_installs = get_installs(app_name:'Microsoft Office Web Apps');

if (!empty_or_null(owa_installs))
{
  foreach owa_install (owa_installs[1])
  {
    if (owa_install['Product'] == '2010')
    {
      owa_2010_path = owa_install['path'];
      owa_2010_sp = owa_install['SP'];
    }
    else if (owa_install['Product'] == '2013')
    {
      owa_2013_path = owa_install['path'];
      owa_2013_sp = owa_install['SP'];
    }
#    else if (owa_install['Product'] == '2019')
#    {
#      owa_2019_path = owa_install['path'];
#      owa_2019_sp = owa_install['SP'];
#    }
  }
}
vuln = FALSE;

####################################################################
# Office Web Apps 2010 SP2
####################################################################
if (owa_2010_path && (!isnull(owa_2010_sp) && owa_2010_sp == '2'))
{
  path = hotfix_append_path(path:owa_2010_path, value:"14.0\WebServices\ConversionService\Bin\Converter");
  if (hotfix_check_fversion(file:'sword.dll', version:'14.0.7236.5000', min_version:'14.0.0.0', path:path, bulletin:bulletin, kb:'4475534', product:'Office Web Apps 2010') == HCF_OLDER)
  vuln = TRUE;
}

######################################################################
# Office Web Apps 2013 SP1
######################################################################
if (owa_2013_path && (!isnull(owa_2013_sp) && owa_2013_sp == '1'))
{
  path = hotfix_append_path(path:owa_2013_path, value:"WordConversionService\bin\Converter");
  if (hotfix_check_fversion(file:'sword.dll', version:'15.0.5163.1000', min_version:'15.0.0.0', path:path, bulletin:bulletin, kb:'4462216', product:'Office Web Apps 2013') == HCF_OLDER)
  vuln = TRUE;
}

####################################################################
# Office Web Apps 2019
####################################################################
#if (owa_2019_path && (!isnull(owa_2019_sp) && owa_2019_sp == '0'))
#{
#  path = hotfix_append_path(path:owa_2019_path, value:'');
#  if (hotfix_check_fversion(file:'msoserver.dll', version:'16.0.10349.20000', min_version:'16.0.0.0', path:path, kb:'4475528', product:'Office Web Apps 2019') == HCF_OLDER)
#  vuln = TRUE;
#}

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
