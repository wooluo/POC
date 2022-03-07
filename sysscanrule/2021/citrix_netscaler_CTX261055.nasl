##
# 
##


include('compat.inc');

if (description)
{
  script_id(149878);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/26");

  script_cve_id("CVE-2019-18225");

  script_name(english:"Citrix ADC Authentication Bypass (CTX261055)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"An authentication bypass vulnerability exists in Citrix Application Delivery Controller (ADC). An unauthenticated,
remote attacker can exploit this, via the web management interface, to bypass authentication and gain administritive
access to the appliance.

Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX261055");
  script_set_attribute(attribute:"solution", value:
"For versions 10.5.x, 11.1.x, 12.0.x, 12.1.x and 13.0.x, upgrade to 10.5.70.5, 11.1.62.8, 12.0.62.8, 12.1.54.13 and 
13.0.41.20, or later, respectively.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18225");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_application_delivery_controller");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_netscaler_detect.nbin");
  script_require_keys("Host/NetScaler/Detected");

  exit(0);
}

var version,build,display_version,fixed_build,report;

version = get_kb_item_or_exit('Host/NetScaler/Version');
build = get_kb_item('Host/NetScaler/Build');

display_version = version + '-' + build;
version = version + '.' + build;

fixed_build = NULL;

if (version =~ '^10\\.5' && ver_compare(ver:build, fix:'70.8', strict:FALSE) == -1)
  fixed_build = '10.5-70.8';

if (version =~ '^11\\.1' && ver_compare(ver:build, fix:'63.9', strict:FALSE) == -1)
  fixed_build = '11.1-63.9';

if (version =~ '^12\\.0' && ver_compare(ver:build, fix:'62.10', strict:FALSE) == -1)
  fixed_build = '12.0-62.10';

if (version =~ '^12\\.1' && ver_compare(ver:build, fix:'54.16', strict:FALSE) == -1)
  fixed_build = '12.1-54.16';

if (version =~ '^13\\.0' && ver_compare(ver:build, fix:'41.28', strict:FALSE) == -1)
  fixed_build = '13.0-41.28';

if (isnull(fixed_build))
  audit(AUDIT_INST_VER_NOT_VULN, 'Citrix NetScaler', display_version);

report =
   '\n  Installed version : ' + display_version +
   '\n  Installed build   : ' + build +
   '\n  Fixed build       : ' + fixed_build +
   '\n';

security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);