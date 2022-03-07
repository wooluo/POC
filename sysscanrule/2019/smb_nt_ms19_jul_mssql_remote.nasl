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
  script_id(126630);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/12 11:33:15");

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

  script_name(english:"Security Updates for Microsoft SQL Server (Uncredentialed Check) (July 2019)");
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

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("mssqlserver_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports(139, 445, 1433, "Services/mssql", "Host/patch_management_checks");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

port = get_service(svc:'mssql', exit_on_fail:TRUE);
instance = get_kb_item('MSSQL/' + port + '/InstanceName');
version = get_kb_item_or_exit('MSSQL/' + port + '/Version');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = pregmatch(pattern:"^([0-9.]+)([^0-9]|$)", string:version);
if(!isnull(ver) && !isnull(ver[1])) ver = ver[1];

if (
    # N/A : 4505218 , 4505220 , 4505221

    # 2014 GDR
    # KB4505417
    ver_compare(minver:'12.0.5200.0', ver:ver, fix:'12.0.5223.0', strict:FALSE) < 0 ||
    # 2014 CU + GDR
    # KB4505419
    ver_compare(minver:'12.0.5500.0', ver:ver, fix:'12.0.5659.0', strict:FALSE) < 0 ||
    # 2014 CU + GDR
    # KB4505422
    ver_compare(minver:'12.0.6200.0', ver:ver, fix:'12.0.6293.0', strict:FALSE) < 0 ||
    # 2016 CU + GDR
    # KB4505222
    ver_compare(minver:'13.0.5300.0', ver:ver, fix:'13.0.5366.0', strict:FALSE) < 0 ||
    # 2017 GDR
    # KB4505224
    ver_compare(minver:'14.0.1000.0', ver:ver, fix:'14.0.2027.0', strict:FALSE) < 0 ||
    # 2017 CU + GDR
    # KB4505225
    ver_compare(minver:'14.0.3006.0', ver:ver, fix:'14.0.3192.0', strict:FALSE) < 0
)
{
  report = '';
  if(!empty_or_null(version)) report += '\n  SQL Server Version   : ' + version;
  if(!empty_or_null(instance)) report += '\n  SQL Server Instance  : ' + instance;
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'MSSQL', version);
