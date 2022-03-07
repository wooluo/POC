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
  script_id(125070);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/12 12:39:17");

  script_cve_id("CVE-2019-0819");
  script_xref(name:"MSKB", value:"4494352");
  script_xref(name:"MSKB", value:"4494351");
  script_xref(name:"MSFT", value:"MS19-4494352");
  script_xref(name:"MSFT", value:"MS19-4494351");

  script_name(english:"Security Updates for Microsoft SQL Server (May 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SQL Server installation on the remote host is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SQL Server installation on the remote host is
missing a security update. It is, therefore, affected by an
information disclosure vulnerability that exists in Microsoft SQL
Server Analysis Services when it improperly enforces metadata
permissions. An attacker who successfully exploited the vulnerability
could query tables or columns for which they do not have access
rights.");
  # https://support.microsoft.com/en-us/help/4494352/security-update-for-sql-server-2017-cu-14-gdr-may-14-2019
  script_set_attribute(attribute:"see_also", value:"");
  # https://support.microsoft.com/en-us/help/4494351/description-of-the-security-update-for-sql-server-2017-gdr-may-14-2019
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4494352
  -KB4494351");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0819");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "mssql_version.nasl", "smb_enum_services.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 1433, "Services/mssql", "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS19-05';
kbs = make_list(
  "4494351",
  "4494352"
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

ver_list = get_kb_list("mssql/installs/*/SQLVersion");

if (isnull(ver_list)) audit(AUDIT_NOT_INST, "Microsoft SQL Server");

program_files_dir = hotfix_get_programfilesdir();
setup_2017_path= program_files_dir + "\Microsoft SQL Server\140\Setup Bootstrap\SQL2017";

foreach item (keys(ver_list))
{
  item -= '/SQLVersion';
  arch = get_kb_item(item + "/arch");
  if (arch != "x64") continue;
  item -= 'mssql/installs/';
  sqlpath = item;

  share = hotfix_path2share(path:sqlpath);
  if (!is_accessible_share(share:share)) continue;

  version = get_kb_item("mssql/installs/" + sqlpath + "/SQLVersion");

  # continue if not SQL Server 2017
  if (version !~ "^14\.0\.") continue;

  if (
    # 2017 GDR
    hotfix_is_vulnerable(path:setup_2017_path, file:"setup.exe", version:"2017.0140.2014.14", min_version:"2017.140.1000.169", bulletin:bulletin, kb:'4494351') ||
    # 2017 CU
    hotfix_is_vulnerable(path:setup_2017_path, file:"setup.exe", version:"2017.0140.3103.01", min_version:"2017.140.3006.16", bulletin:bulletin, kb:'4494352')
  )
  {
    vuln++;
  }
}
hotfix_check_fversion_end();

if (vuln)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  exit(0);
}
else
{
  audit(AUDIT_HOST_NOT, 'affected');
}
