
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
  script_id(125227);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/23 15:49:41");

  script_cve_id(
    "CVE-2019-0949",
    "CVE-2019-0950",
    "CVE-2019-0951",
    "CVE-2019-0952",
    "CVE-2019-0956",
    "CVE-2019-0957",
    "CVE-2019-0958",
    "CVE-2019-0963"
  );
  script_bugtraq_id(
    108198,
    108201,
    108203,
    108209,
    108213,
    108215,
    108216,
    108218
  );
  script_xref(name:"MSKB", value:"4464573");
  script_xref(name:"MSKB", value:"4464564");
  script_xref(name:"MSKB", value:"4464556");
  script_xref(name:"MSKB", value:"4464549");
  script_xref(name:"MSFT", value:"MS19-4464573");
  script_xref(name:"MSFT", value:"MS19-4464564");
  script_xref(name:"MSFT", value:"MS19-4464556");
  script_xref(name:"MSFT", value:"MS19-4464549");

  script_name(english:"Security Updates for Microsoft SharePoint Server (May 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server installation on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities :

  - An information disclosure vulnerability exists when
    Microsoft SharePoint Server does not properly sanitize a
    specially crafted web request to an affected SharePoint
    server. An authenticated attacker could exploit the
    vulnerability by sending a specially crafted request to
    an affected SharePoint server. The attacker who
    successfully exploited the vulnerability could then
    perform cross-site scripting attacks on affected systems
    and run script in the security context of the current
    user. These attacks could allow the attacker to read
    content that the attacker is not authorized to read, use
    the victim's identity to take actions on the SharePoint
    site on behalf of the user, such as change permissions
    and delete content, and inject malicious content in the
    browser of the user. The security update addresses the
    vulnerability by helping to ensure that SharePoint
    Server properly sanitizes web requests. (CVE-2019-0956)

  - An elevation of privilege vulnerability exists when
    Microsoft SharePoint Server does not properly sanitize a
    specially crafted web request to an affected SharePoint
    server. An authenticated attacker could exploit the
    vulnerability by sending a specially crafted request to
    an affected SharePoint server. The attacker who
    successfully exploited the vulnerability could then
    perform cross-site scripting attacks on affected systems
    and run script in the security context of the current
    user. These attacks could allow the attacker to read
    content that the attacker is not authorized to read, use
    the victim's identity to take actions on the SharePoint
    site on behalf of the user, such as change permissions
    and delete content, and inject malicious content in the
    browser of the user. The security update addresses the
    vulnerability by helping to ensure that SharePoint
    Server properly sanitizes web requests. (CVE-2019-0957,
    CVE-2019-0958)

  - A remote code execution vulnerability exists in
    Microsoft SharePoint Server when it fails to properly
    identify and filter unsafe ASP.Net web controls. An
    authenticated attacker who successfully exploited the
    vulnerability could use a specially crafted page to
    perform actions in the security context of the
    SharePoint application pool process.  (CVE-2019-0952)

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
    Server properly sanitizes web requests. (CVE-2019-0963)

  - A spoofing vulnerability exists when Microsoft
    SharePoint Server does not properly sanitize a specially
    crafted web request to an affected SharePoint server. An
    authenticated attacker could exploit the vulnerability
    by sending a specially crafted request to an affected
    SharePoint server. The attacker who successfully
    exploited the vulnerability could then perform cross-
    site scripting attacks on affected systems and run
    script in the security context of the current user.
    These attacks could allow the attacker to read content
    that the attacker is not authorized to read, use the
    victim's identity to take actions on the SharePoint site
    on behalf of the user, such as change permissions and
    delete content, and inject malicious content in the
    browser of the user. The security update addresses the
    vulnerability by helping to ensure that SharePoint
    Server properly sanitizes web requests. (CVE-2019-0949,
    CVE-2019-0950, CVE-2019-0951)");
  # https://support.microsoft.com/en-ie/help/4464573/description-of-the-security-update-for-sharepoint-foundation-2010-may
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-ie/help/4464564/description-of-the-security-update-for-sharepoint-foundation-2013-may
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4464556/description-of-the-security-update-for-sharepoint-server-2019-may-14
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4464549/description-of-the-security-update-for-sharepoint-enterprise-server
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4464573
  -KB4464564
  -KB4464556
  -KB4464549");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0952");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/16");

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

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('misc_func.inc');
include('install_func.inc');
include('lists.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS19-05';

kbs = make_list(
  '4464549', # 2016
  '4464556', # 2019
  '4464564', # 2013
  '4464573'  # 2010
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, 'Failed to determine the location of %windir%.');

registry_init();

vuln = FALSE;
port = kb_smb_transport();

install = get_single_install(app_name:'Microsoft SharePoint Server');

# direct reference lookup of product...
kb_checks =
{
  '2010':
  # direct reference lookup of SP...
  { '2':
    # direct reference lookup of edition...
    { 'Foundation':
      [{
        'kb'           : '4464573',
        'product_name' : 'Microsoft SharePoint Foundation Server 2010 SP 2'
      }]
    }
  },
  '2013':
  # direct reference lookup of SP...
  { '1':
    # direct reference lookup of edition...
    { 'Foundation':
      [{
        'kb'           : '4464564',
        'path'         : hotfix_get_commonfilesdir(),
        'append'       : 'microsoft shared\\Web Server Extensions\\15\\config\\bin',
        'file'         : 'stssoap.dll',
        'version'      : '15.0.4981.1000',
        'product_name' : 'Microsoft SharePoint Foundation Server 2013 SP 1'
      }]
    }
  },
  '2016':
  # direct reference lookup of SP...
  { '0':
    # direct reference lookup of edition...
    { 'Server':
      [{
        'kb'           : '4464549',
        'path'         : install['path'],
        'append'       : 'TransformApps',
        'file'         : 'docxpageconverter.exe',
        'version'      : '16.0.4849.1000',
        'product_name' : 'Microsoft SharePoint Server 2016'
      }]
    }
  },
  '2019':
  # direct reference lookup of SP...
  { '0':
    # direct reference lookup of edition...
    { 'Server':
      [{
        'kb'           : '4464556',
        'path'         : install['path'],
        'append'       : 'BIN',
        'file'         : 'ascalc.dll',
        'version'      : '16.0.10345.12101',
        'product_name' : 'Microsoft SharePoint Enterprise Server 2019'
      }]
    }
  }
};

# get the specific product / path 
params = kb_checks[install['Product']][install['SP']][install['Edition']][0];
# audit if not affected
if (isnull(params)) audit(AUDIT_INST_VER_NOT_VULN, "Microsoft SharePoint Server");

are_we_vuln = HCF_OLDER;

if (empty_or_null(params['file']) && get_kb_item("SMB/Registry/Uninstall/Enumerated"))
{
  display_names = get_kb_list_or_exit('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
  if (display_names)
  {
    foreach item (keys(display_names))
    {
      if ('KB'+params['kb'] >< display_names[item])
      {
        are_we_vuln = HCF_OK;
        break;
      }
    }

    if (are_we_vuln)
    {
      report = '\n';
      if (params['product_name'])
        report += '  Product : ' + params['product_name'] + '\n';
      if (params['kb'])
        report += '  KB : ' + params['kb'] + '\n';
      hotfix_add_report(report, kb:params['kb']);
    }
  }
}
else
{
  # grab the path otherwise
  path = hotfix_append_path(path:params['path'], value:params['append']);
  # then - check if we are vuln
  are_we_vuln = hotfix_check_fversion(file:params['file'], version:params['version'], path:path, kb:params['kb'], product:params['product_name']);
}

xss = FALSE;

if (params['kb'] == '4464564')
  xss = TRUE;

if (are_we_vuln == HCF_OLDER)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  if (xss) replace_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
