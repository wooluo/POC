#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125258);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/17 16:59:37");

  script_cve_id("CVE-2019-12044");

  script_name(english:"Citrix ADC and Citrix NetScaler Gateway buffer overflow vulnerability (CTX249976)");
  script_summary(english:"Checks the Citrix NetScaler version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix ADC or Citrix NetScaler Gateway device is affected by a buffer overflow vulnerability.
An attacker may be able to leverage this vulnerability which will result in a 
denial of service in a specific configuration.
Please refer to advisory CTX249976 for more information.");

  # https://support.citrix.com/article/CTX249976
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Citrix NetScaler Gateway version 11.1 build 59.10 / 12.0 build 59.8 / 12.1 build 49.23
or refer to vendor documentation for configuration mitigation.");

  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12044");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:citrix:netscaler_access_gateway_firmware");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_netscaler_detect.nbin");
  script_require_keys("Host/NetScaler/Detected", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');

# Multiple models are not affected and a mitigation strategy is provided
if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_name = 'Citrix NetScaler';
version = get_kb_item_or_exit('Host/NetScaler/Version');
build = get_kb_item('Host/NetScaler/Build');
enhanced = get_kb_item('Host/NetScaler/Enhanced');
fixed_build = NULL;

if (isnull(build)) exit(0, 'The build number of ' + app_name + ' ' + version + ' could not be determined.');

display_version = version + '-' + build;
version = version + '.' + build;

if (!enhanced)
{
  if (version =~ '^10\\.5' && ver_compare(ver:build, fix:'70.0') < 0)
  {
    fixed_build = 'Apply the configuration mitigation as per advisory or upgrade to a fixed version';
  }
  else if (version =~ '^11\\.1' && ver_compare(ver:build, fix:'59.10') < 0)
  {
    fixed_build = '59.10';
  }
  else if (version =~ '^12\\.0' && ver_compare(ver:build, fix:'59.8') < 0)
  {
    fixed_build = '59.8';
  }
  else if (version =~ '^12\\.1' && ver_compare(ver:build, fix:'49.23') < 0)
  {
    fixed_build = '49.23';
  }
}

if (isnull(fixed_build))
{
  audit(AUDIT_INST_VER_NOT_VULN, app_name, display_version);
}

report =
   '\n  Installed version : ' + display_version +
   '\n  Installed build   : ' + build +
   '\n  Fixed build       : ' + fixed_build +
   '\n';

security_report_v4(port:0, severity:SECURITY_WARNING, extra:report, xss: TRUE);
