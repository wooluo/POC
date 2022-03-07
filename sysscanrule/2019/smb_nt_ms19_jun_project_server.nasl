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
  script_id(125831);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/12 12:39:17");

  script_cve_id(
    "CVE-2019-1033",
    "CVE-2019-1036"
  );
  script_xref(name:"MSKB", value:"4092442");
  script_xref(name:"MSFT", value:"MS19-4092442");

  script_name(english:"Security Updates for Microsoft Project Server (June 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Project Server installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Project Server installation on the remote host
is missing security updates. It is, therefore, affected by
multiple vulnerabilities :

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
    Server properly sanitizes web requests. (CVE-2019-1033,
    CVE-2019-1036)");
  # https://support.microsoft.com/en-us/help/4092442/security-update-for-project-server-2010-june-11-2019
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB4092442 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1033");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:project_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_sharepoint_installed.nbin","smb_hotfixes.nasl","ms_bulletin_checks_possible.nasl","microsoft_project_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('misc_func.inc');
include('install_func.inc');
include('lists.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS19-06';

kbs = make_list('4092442');

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, 'Failed to determine the location of %windir%.');

registry_init();

vuln = FALSE;
port = kb_smb_transport();

install = get_single_install(app_name:'Microsoft Project Server');

# direct reference lookup of product...
kb_checks =
{
  '2010':
  # direct reference lookup of SP...
  { '2':
    [{
      'kb': '4092442',
      'path': install['path'],
      'append':'bin',
      'file':'microsoft.office.project.server.pwa.dll',
      'version':'14.0.7234.5000',
      'min_version':'14.0.0.0',
      'product_name':'Microsoft Project Server 2010 SP2'
    }]
  }
};

# get the specific product / path 
param_list = kb_checks[install['Product']][install['SP']][install['Edition']];

# audit if not affected
if(isnull(param_list)) audit(AUDIT_INST_VER_NOT_VULN, "Microsoft SharePoint Server");

vuln = FALSE;
# grab the path otherwise
foreach check (param_list)
{
  path = hotfix_append_path(path:check['path'], value:check['append']);
  are_we_vuln = hotfix_check_fversion(file:check['file'], version:check['version'], path:path, kb:check['kb'], product:check['product_name']);
  if (are_we_vuln == HCF_OLDER)
      vuln = TRUE;
}

if (vuln == TRUE)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  replace_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
