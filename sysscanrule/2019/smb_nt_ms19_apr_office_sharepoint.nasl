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
  script_id(123955);
  script_version("1.4");
  script_cvs_date("Date: 2019/05/17 15:06:54");

  script_cve_id(
    "CVE-2019-0830",
    "CVE-2019-0831"
  );
  script_xref(name:"MSKB", value:"4464510");
  script_xref(name:"MSKB", value:"4464511");
  script_xref(name:"MSKB", value:"4464515");
  script_xref(name:"MSKB", value:"4464518");
  script_xref(name:"MSKB", value:"4464525");
  script_xref(name:"MSKB", value:"4464528");
  script_xref(name:"MSFT", value:"MS19-4464510");
  script_xref(name:"MSFT", value:"MS19-4464511");
  script_xref(name:"MSFT", value:"MS19-4464515");
  script_xref(name:"MSFT", value:"MS19-4464518");
  script_xref(name:"MSFT", value:"MS19-4464525");
  script_xref(name:"MSFT", value:"MS19-4464528");

  script_name(english:"Security Updates for Microsoft SharePoint Server (April 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server installation on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities :

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
    Server properly sanitizes web requests. (CVE-2019-0830,
    CVE-2019-0831)");
  # https://support.microsoft.com/en-us/help/4464510/description-of-the-security-update-for-sharepoint-enterprise-server
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4464511/description-of-the-security-update-for-sharepoint-enterprise-server
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4464515/description-of-the-security-update-for-sharepoint-foundation-2013
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4464525/description-of-the-security-update-for-sharepoint-server-2010-april-9
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4464528/description-of-the-security-update-for-sharepoint-foundation-2010
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4464518/description-of-the-security-update-for-sharepoint-server-2019-april-9
  script_set_attribute(attribute:"see_also", value:"");

  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4464510
  -KB4464511
  -KB4464515
  -KB4464518
  -KB4464525
  -KB4464528");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0830");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/09");

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

bulletin = "MS19-04";

kbs = make_list(
  '4464525', # 2010
  '4464528', # 2013
  '4464511', # 2013
  '4464515', # 2016
  '4464510', # 2019
  '4464518'  # 2019
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, 'Failed to determine the location of %windir%.');

registry_init();

vuln = FALSE;
port = kb_smb_transport();

install = get_single_install(app_name:'Microsoft SharePoint Server');

# direct reference lookup of product...
kb_checks =
{ '2010': 
  # direct reference lookup of SP...
  { '2':
    # direct reference lookup of edition...
    {'Server': 
      # list of KB's
      [
        {
          'kb': '4464525',
          'path':hotfix_get_commonfilesdir(),    
          'append':'Microsoft Shared\\Web Server Extensions\\14\\ISAPI', 
          'file':'microsoft.office.server.search.dll',  
          'version':'14.0.7232.5000',   
          'min_version':'14.0.0.0000',    
          'product_name':'Microsoft SharePoint Enterprise Server 2010 SP 2'
        }
      ]
    ,
    'Foundation':
      # multiple kb's are possible - each one checks a different location / file indicator
      [
        {
          'kb': '4464528',
          'path':hotfix_get_commonfilesdir(),    
          'append':'Microsoft Shared\\Web Server Extensions\\14\\ISAPI', 
          'file':'microsoft.office.server.search.dll',  
          'version':'14.0.7232.5000',   
          'min_version':'14.0.0.0000',    
          'product_name':'Microsoft SharePoint Foundation Server 2010 SP 2'
        }
      ]
    }
  }
,
'2013': 
  # direct reference lookup of SP...
  { '1':
    # direct reference lookup of edition...
    {'Server': 
      [
        {
          'kb': '4464511',
          'path': install['path'],    
          'append':'WebServices\\ConversionServices', 
          'file':'msoserver.dll',  
          'version':'15.0.5127.1000',   
          'min_version':'15.0.0.0000',    
          'product_name':'Microsoft SharePoint Enterprise Server 2013 SP 1'
        }
      ]
    ,
    'Foundation':
      # multiple kb's are possible - each one checks a different location / file indicator
      [
        {
          'kb': '4464515',
          'path': hotfix_get_commonfilesdir(),    
          'append':'Microsoft Shared\\Web Server Extensions\\15\\bin', 
          'file':'onetutil.dll',  
          'version':'15.0.5127.1000',   
          'min_version':'15.0.0.0000',    
          'product_name':'Microsoft SharePoint Foundation Server 2013 SP 1'
        }
      ]
    }
   },
  '2016': 
    # direct reference lookup of SP...
    { '0':
      # direct reference lookup of edition...
      {'Server': 
        [
          {
            'kb': '4464510',
            'path': hotfix_get_commonfilesdir(),    
            'append':'Microsoft Shared\\Web Server Extensions\\16\\bin', 
            'file':'onetutil.dll',  
            'version':'16.0.4834.1000',   
            'min_version':'16.0.0.0000',    
            'product_name':'Microsoft SharePoint Server 2016'
          }
        ]
      }
    },
  '2019': 
    # direct reference lookup of SP...
    { '0':
      # direct reference lookup of edition...
      {'Server': 
        [
          {
            'kb': '4464518',
            'path': install['path'],    
            'append':'WebServices\\ConversionServices', 
            'file':'sword.dll',  
            'version':'16.0.10343.20000',   
            'min_version':'16.0.10000.0',    
            'product_name':'Microsoft SharePoint Enterprise Server 2019'
          }
        ]
      }
    }
};

hotfix_check_fversion_params = kb_checks[install['Product']][install['SP']][install['Edition']];

foreach params (hotfix_check_fversion_params)
{
  path = hotfix_append_path(path:params['path'], value:params['append']);
  are_we_vuln = hotfix_check_fversion(file:params['file'], version:params['version'], path:path, kb:params['kb'], product:params['product_name']);
  if (are_we_vuln == HCF_OLDER)
  {
     vuln = TRUE;  
  }
}

# check for vuln and report... 
if (vuln)
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
