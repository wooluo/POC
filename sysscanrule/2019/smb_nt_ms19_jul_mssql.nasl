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
  script_id(126631);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/13  6:06:32");

  script_cve_id("CVE-2019-1068");
  script_bugtraq_id(108954);
  script_xref(name:"MSKB", value:"4505217");
  script_xref(name:"MSKB", value:"4505419");
  script_xref(name:"MSKB", value:"4505422");
  script_xref(name:"MSKB", value:"4505218");
  script_xref(name:"MSKB", value:"4505219");
  script_xref(name:"MSKB", value:"4505225");
  script_xref(name:"MSKB", value:"4505224");
  script_xref(name:"MSKB", value:"4505222");
  script_xref(name:"MSKB", value:"4505221");
  script_xref(name:"MSKB", value:"4505220");
  script_xref(name:"MSFT", value:"MS19-4505217");
  script_xref(name:"MSFT", value:"MS19-4505419");
  script_xref(name:"MSFT", value:"MS19-4505422");
  script_xref(name:"MSFT", value:"MS19-4505218");
  script_xref(name:"MSFT", value:"MS19-4505219");
  script_xref(name:"MSFT", value:"MS19-4505225");
  script_xref(name:"MSFT", value:"MS19-4505224");
  script_xref(name:"MSFT", value:"MS19-4505222");
  script_xref(name:"MSFT", value:"MS19-4505221");
  script_xref(name:"MSFT", value:"MS19-4505220");
  script_xref(name:"IAVA", value:"2019-A-0226");

  script_name(english:"Security Updates for Microsoft SQL Server (July 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SQL Server installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SQL Server installation on the remote host is
missing a security update. It is, therefore, affected by the
following vulnerability :

  - A remote code execution vulnerability exists in
    Microsoft SQL Server when it incorrectly handles
    processing of internal functions. An attacker who
    successfully exploited this vulnerability could execute
    code in the context of the SQL Server Database Engine
    service account.  (CVE-2019-1068)");
  # https://support.microsoft.com/en-us/help/4505217/security-update-for-sql-server-2014-sp2-gdr-july-9-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4505419/description-of-the-security-update-for-sql-server-2014-sp2-cu17-gdr-ju
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4505422/security-update-for-sql-server-2014-sp3-cu3-gdr-july-9-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4505218/description-of-the-security-update-for-sql-server-2014-sp3-gdr-july-9
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4505219/security-update-for-sql-server-2016-sp1-gdr-july-9-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4505225/security-update-for-sql-server-2017-cu15-gdr-july-9-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4505224/description-of-the-security-update-for-sql-server-2017-gdr-july-9-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4505222/security-update-for-sql-server-2016-sp2-cu7-gdr-july-9-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4505221/description-of-the-security-update-for-sql-server-2016-sp1-cu15-gdr-ju
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4505220/security-update-for-sql-server-2016-sp2-gdr-july-9-2019
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4505217
  -KB4505419
  -KB4505422
  -KB4505218
  -KB4505219
  -KB4505225
  -KB4505224
  -KB4505222
  -KB4505221
  -KB4505220");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1068");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "mssql_version.nasl", "smb_enum_services.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 1433, "Services/mssql", "Host/patch_management_checks");

  exit(0);
}

include('audit.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('misc_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

kbs = make_list(
  '4505217',
  '4505218',
  '4505219',
  '4505220',
  '4505221',
  '4505222',
  '4505224',
  '4505225',
  '4505419',
  '4505422'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

vuln = 0;
ver_list = get_kb_list('mssql/installs/*/SQLVersion');
program_files_dir = hotfix_get_programfilesdir();
program_files_x86_dir = hotfix_get_programfilesdirx86();

if (isnull(ver_list)) audit(AUDIT_NOT_INST, 'Microsoft SQL Server');

foreach item (keys(ver_list))
{
  item -= '/SQLVersion';

  arch = get_kb_item(item + '/arch');

  item -= 'mssql/installs/';
  sqlpath = item;

  share = hotfix_path2share(path:sqlpath);

  if (!is_accessible_share(share:share)) continue;

  version = get_kb_item('mssql/installs/' + sqlpath + '/SQLVersion');

  if(empty_or_null(version)) continue;


  ############
  # 2014
  ############
  if (version =~ "^12\.0\.")
  { 
    sqlpath = '\\Microsoft SQL Server\\120\\Setup Bootstrap\\SQLServer2014';
    if(
      # 2014 SP2 GDR
      # KB 4505217
      hotfix_is_vulnerable(path:program_files_dir + sqlpath, file:'setup.exe', version:'2014.120.5223.6', min_version:'2014.120.5000.0', kb:'4505217') ||
      (arch == 'x86' &&
      hotfix_is_vulnerable(path:program_files_x86_dir + sqlpath, file:'setup.exe', version:'2014.120.5223.6', min_version:'2014.120.5000.0', kb:'4505217')
      ) ||

      # 2014 SP2 CU17 + GDR
      # KB 4505419
      hotfix_is_vulnerable(path:program_files_dir + sqlpath, file:'setup.exe', version:'2014.120.5659.1', min_version:'2014.120.5300.0', kb:'4505419') ||
      (arch == 'x86' &&
      hotfix_is_vulnerable(path:program_files_x86_dir + sqlpath, file:'setup.exe', version:'2014.120.5659.1', min_version:'2014.120.5300.0', kb:'4505419')
      ) ||

      # 2014 SP3 GDR
      # KB 4505418
      hotfix_is_vulnerable(path:program_files_dir + sqlpath, file:'setup.exe', version:'2014.120.6108.1', min_version:'2014.120.6100.0', kb:'4505418') ||
      (arch == 'x86' &&
      hotfix_is_vulnerable(path:program_files_x86_dir + sqlpath, file:'setup.exe', version:'2014.120.6108.1', min_version:'2014.120.6100.0', kb:'4505418')
      ) ||

      # 2014 SP3 CU3 + GDR
      # KB 4505422
      hotfix_is_vulnerable(path:program_files_dir + sqlpath, file:'setup.exe', version:'2014.120.6293.0', min_version:'2014.120.6200.0', kb:'4505422') ||
      (arch == 'x86' &&
      hotfix_is_vulnerable(path:program_files_x86_dir + sqlpath, file:'setup.exe', version:'2014.120.6293.0', min_version:'2014.120.6200.0', kb:'4505422')
      )
    )
      vuln++;
  }


  ############
  # 2016
  ############
  else if (version =~ "^13\.0\.")
  {
    sqlpath = '\\Microsoft SQL Server\\130\\Setup Bootstrap\\SQLServer2016';
    if(
       # 2016 SP1 GDR
       # KB 4505219
       hotfix_is_vulnerable(path:program_files_dir + sqlpath, file:'setup.exe', version:'2015.130.4259.0', min_version:'2015.130.4000.0', kb:'4505219') ||
       (arch == 'x86' &&
       hotfix_is_vulnerable(path:program_files_x86_dir + sqlpath, file:'setup.exe', version:'2015.130.4259.0', min_version:'2015.130.4000.0', kb:'4505219')
       ) ||

       # 2016 SP1 CU15 + GDR
       # KB 4505221
       hotfix_is_vulnerable(path:program_files_dir + sqlpath, file:'setup.exe', version:'2015.130.4466.4', min_version:'2015.130.4400.0', kb:'4505221') ||
       (arch == 'x86' &&
       hotfix_is_vulnerable(path:program_files_x86_dir + sqlpath, file:'setup.exe', version:'2015.130.4466.4', min_version:'2015.130.4400.0', kb:'4505221')
       ) ||

       # 2016 SP2 GDR
       # KB 4505220
       #  - x64 only
       (arch == 'x64' &&
        hotfix_is_vulnerable(path:program_files_dir + sqlpath, file:'setup.exe', version:'2015.131.5101.9', min_version:'2015.131.5000.0', kb:'4505220')
       ) ||

       # 2016 SP2 CU7 + GDR
       # KB 4505222
       #  - x64 only
      (arch == 'x64' &&
       hotfix_is_vulnerable(path:program_files_dir + sqlpath, file:'setup.exe', version:'2015.131.5366.0', min_version:'2015.131.5250.0', kb:'4505222')
      )
    )
      vuln++;
  }


  ############
  # 2017
  ############
  else if ( version =~ "^14\.0\.")
  {
    sqlpath = '\\Microsoft SQL Server\\140\\Setup Bootstrap\\SQL2017';
    if(
      # 2017 GDR
      # KB 4505224
      #  - x64 only
      (arch == 'x64' &&
      hotfix_is_vulnerable(path:program_files_dir + sqlpath, file:'setup.exe', version:'2017.140.2021.2', min_version:'2017.140.1000.0', kb:'4505224')
      ) ||

      # 2017 CU15 + GDR
      # KB 4505225
      #  - x64 only
      (arch == 'x64' &&
      hotfix_is_vulnerable(path:program_files_dir + sqlpath, file:'setup.exe', version:'2017.140.3192.2', min_version:'2017.140.3000.0', kb:'4505225')
      )
    )
      vuln++;
  }
}

hotfix_check_fversion_end();

if (vuln)
{
  hotfix_security_hole();
  exit(0);
}
audit(AUDIT_HOST_NOT, 'affected');
