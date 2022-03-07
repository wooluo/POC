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
  script_id(127909);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/16 17:04:56");

  script_cve_id(
    "CVE-2019-1201",
    "CVE-2019-1202",
    "CVE-2019-1203",
    "CVE-2019-1205"
  );
  script_xref(name:"MSKB", value:"4462137");
  script_xref(name:"MSKB", value:"4475530");
  script_xref(name:"MSKB", value:"4475549");
  script_xref(name:"MSKB", value:"4475555");
  script_xref(name:"MSKB", value:"4475557");
  script_xref(name:"MSKB", value:"4475565");
  script_xref(name:"MSKB", value:"4475575");
  
  script_xref(name:"MSFT", value:"MS19-4462137");
  script_xref(name:"MSFT", value:"MS19-4475530");
  script_xref(name:"MSFT", value:"MS19-4475549");
  script_xref(name:"MSFT", value:"MS19-4475555");
  script_xref(name:"MSFT", value:"MS19-4475557");
  script_xref(name:"MSFT", value:"MS19-4475565");
  script_xref(name:"MSFT", value:"MS19-4475575");
  script_xref(name:"IAVA", value:"2019-A-0289");

  script_name(english:"Security Updates for Microsoft SharePoint Server (August 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server installation on the remote
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
    CVE-2019-1205)

  - An information disclosure vulnerability exists in the
    way Microsoft SharePoint handles session objects. A
    locally authenticated attacker who successfully
    exploited the vulnerability could hijack the session of
    another user.  (CVE-2019-1202)

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
    Server properly sanitizes web requests. (CVE-2019-1203)
  ");
  # https://support.microsoft.com/en-us/help/4462137/security-update-for-sharepoint-enterprise-server-2013
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4475530/security-update-for-sharepoint-server-2010-august-13
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4475549/security-update-for-sharepoint-enterprise-server-2016
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4475555/security-update-for-sharepoint-server-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4475557/security-update-for-sharepoint-enterprise-server
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4475565/security-update-for-sharepoint-foundation-2013-august-13
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4475575/security-update-for-sharepoint-foundation-2013-august-13
  script_set_attribute(attribute:"see_also", value:"");


  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4462137
  -KB4475530
  -KB4475549
  -KB4475555
  -KB4475557
  -KB4475565
  -KB4475575
  ");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1201");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

bulletin = 'MS19-08';

kbs = make_list(
  '4475530', # 2010 SP2
  '4475575', # 2010 SP2
  '4475565', # 2013 SP1 Foundation
  '4462137', # 2013 SP1 Enterprise
  '4475557', # 2013 SP1 Enterprise
  '4475549', # 2016
  '4475555'  # 2019
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

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
    {'Server':
      [{
        'kb': '4475530',
        'path': install['path'],
        'append':'webservices\\wordserver\\core',
        'file':'sword.dll',
        'version':'14.0.7236.5000',
        'min_version':'14.0.0.0',
        'product_name':'Microsoft SharePoint Server 2010 SP2'
      }],
      'Foundation':
      [{
        'kb': '4475575',
        'path': hotfix_get_commonfilesdir(),
        'append':'microsoft shared\\web server extensions\\14\\isapi',
        'file':'microsoft.sharepoint.dll',
        'version':'14.0.7236.5000',
        'min_version':'14.0.0.0',
        'product_name':'Microsoft SharePoint Foundation Server 2010 SP2'
      }]
    }
  },
  '2013':
  # direct reference lookup of SP...
  { '1':
    # direct reference lookup of edition...
    {'Server':
      [{
        'kb': '4462137',
        'path': install['path'],    
        'append':'webservices\\conversionservices', 
        'file':'sword.dll',  
        'version':'15.0.5163.1000',
        'min_version':'15.0.0.0',
        'product_name':'Microsoft SharePoint Enterprise Server 2013 SP1'
      },
      {
        'kb': '4475557',
        'path': install['path'],    
        'append':'bin', 
        'file':'nl7data0011.dll',  
        'version':'15.0.5163.1000',
        'min_version':'15.0.0.0',
        'product_name':'Microsoft SharePoint Enterprise Server 2013 SP1'
      }],
    'Foundation':
      [{
        'kb': '4475565',
        'path': hotfix_get_commonfilesdir(),
        'append':'microsoft shared\\web server extensions\\15\\bin',
        'file':'onetutil.dll', 
        'version':'15.0.5163.1000',
        'min_version':'15.0.0.0',
        'product_name':'Microsoft SharePoint Foundation Server 2013 SP1'
      }]
    }
  },
  '2016':
  # direct reference lookup of SP...
  { '0':
    # direct reference lookup of edition...
    {'Server':
      [{
        'kb': '4475549',
        'path': install['path'],
        'append':'transformapps',
        'file':'docxpageconverter.exe',
        'version':'16.0.4888.1000',
        'min_version':'16.0.0.0',
        'product_name':'Microsoft SharePoint Enterprise Server 2016'
      }]
    }
  },
  '2019':
  # direct reference lookup of SP...
  { '0':
    # direct reference lookup of edition...
    {'Server':
      [{
        'kb': '4475555',
        'path': install['path'],
        'append':'bin',
        'file':'microsoft.sharepoint.publishing.dll',
        'version':'16.0.10349.20000',
        'min_version':'16.0.10000.0',
        'product_name':'Microsoft SharePoint Server 2019'
      }]
    }
  }
};

# get the specific product / path 
param_list = kb_checks[install['Product']][install['SP']][install['Edition']];

# audit if not affected
if(isnull(param_list)) audit(AUDIT_INST_VER_NOT_VULN, "Microsoft SharePoint Server");

vuln = FALSE;
xss = FALSE;
# grab the path otherwise
foreach check (param_list)
{
  path = hotfix_append_path(path:check['path'], value:check['append']);
  are_we_vuln = hotfix_check_fversion(file:check['file'], version:check['version'], path:path, kb:check['kb'], product:check['product_name']);
  if (are_we_vuln == HCF_OLDER)
  {
    if (check['kb'] == '4475555' || check['kb'] == '4475557' ||  check['kb'] == '4475549') xss = TRUE;
    vuln = TRUE;
  }
}

if (vuln == TRUE)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  if (xss) replace_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}