#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126601);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/12 12:39:17");

  script_cve_id("CVE-2019-1075");
  script_bugtraq_id(108984);
  script_xref(name:"IAVB", value:"2019-B-0058");

  script_name(english:"Security Update for Microsoft ASP.NET Core (July 2019)");
  script_summary(english:"Checks the version of Microsoft ASP.NET Core packages.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft ASP.NET Core installations on the remote host contain vulnerable packages.");
  script_set_attribute(attribute:"description", value:
"The Microsoft ASP.NET Core installation on the remote host is version 2.1.x < 2.1.12, 2.2.x < 2.2.6.
It is, therefore, affected by a spoofing vulnerability that could lead to an open redirect.
An unauthenticated, remote attacker could exploit this issue, via a link that has a specially crafted URL,
and convince the user to click the link that will redirect a targeted user to a malicious website");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2019-1075
  script_set_attribute(attribute:"see_also", value:"");
  # https://github.com/aspnet/Announcements/issues/373
  script_set_attribute(attribute:"see_also", value:"");
  # https://github.com/aspnet/AspNetCore/issues/12007
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update ASP.NET Core, remove vulnerable packages and refer to vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1075");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:aspnet_core");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_asp_dotnet_core_win.nbin");
  script_require_keys("installed_sw/ASP .NET Core Windows");
  script_require_ports(139, 445);

  exit(0);
}

include('global_settings.inc');
include('audit.inc');
include('install_func.inc');
include('misc_func.inc');
include('smb_func.inc');
include('vcf.inc');

appname = 'ASP .NET Core Windows';
port = kb_smb_transport();
vuln = FALSE;
install = get_single_install(app_name:appname);

report =
  '\n  Path              : ' + install['path'] +
  '\n  Installed version : ' + install['version'] +
  '\n';

package_dat = {
  'Microsoft.AspNetCore.All':{
    'constraints':[
      { 'min_version' : '2.1.0', 'fixed_version' : '2.1.12' },
      { 'min_version' : '2.2.0', 'fixed_version' : '2.2.6' }
    ]
  },
  'Microsoft.AspNetCore.App':{
    'constraints':[
      { 'min_version' : '2.1.0', 'fixed_version' : '2.1.12' },
      { 'min_version' : '2.2.0', 'fixed_version' : '2.2.6' }
    ]
  },
  'Microsoft.AspNetCore.Server.IIS':{
    'constraints':[
      { 'min_version' : '2.2.0', 'max_version' : '2.2.2', 'fixed_version' : '2.2.6' }
    ]
  },
  'Microsoft.AspNetCore.Server.HttpSys':{
    'constraints':[
      { 'min_version' : '2.1.0', 'max_version' : '2.1.1', 'fixed_version' : '2.1.12' },
      { 'equal' : '2.2.0', 'fixed_version' : '2.2.6' }
    ]
  }
};

foreach package (keys(package_dat))
{
  foreach instance (split(install[package], sep:';', keep:false))
  {
    inst = split(instance, sep:'?', keep:false);
    out = vcf::check_version(version:vcf::parse_version(inst[0]), constraints:package_dat[package]['constraints']);
    if(!vcf::is_error(out) && !isnull(out))
    {
      vuln = TRUE;
      report +=
        '\n  Package           : ' + package +
        '\n  Path              : ' + inst[1] +
        '\n  Installed version : ' + inst[0] +
        '\n  Fixed version     : ' + out['fixed_version'] +
        '\n';
    }
  }
}

if(!vuln) audit(AUDIT_INST_VER_NOT_VULN, appname + ' ' + install['version']);

security_report_v4(port:port, severity:SECURITY_WARNING, extra:report);
