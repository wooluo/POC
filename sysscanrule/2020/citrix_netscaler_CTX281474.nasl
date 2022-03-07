#
# 
#
include('compat.inc');

if (description)
{
  script_id(140790);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/25");

  script_cve_id("CVE-2020-8245", "CVE-2020-8246", "CVE-2020-8247");
  script_xref(name:"IAVA", value:"2020-A-0434");

  script_name(english:"Citrix ADC and Citrix NetScaler Gateway Multiple Vulnerabilities (CTX281474)");

  script_set_attribute(attribute:"synopsis", value:"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix ADC or Citrix NetScaler Gateway device is version 11.1.x prior to 11.1.65.12, 12.1.x prior to 
12.1.58.15 or 13.0.x prior to 13.0.64.35. It is, therefore, affected by multiple vulnerabilities:
  - A HTML injection vulnerability exists in Citrix ADC due to improper validation of user-supplied input. 
  An unauthenticated, remote attacker can exploit this to inject arbitrary content into responses generated
  by the application (CVE-2020-8245).

  - A denial of service (DoS) vulnerability exists in Citrix ADC. An unauthenticated, remote attacker can 
  exploit this issue, to impose a DoS condition on the application (CVE-2020-8246).

  - A privilege escalation vulnerability exists in management interface component. An authenticated, 
  remote attacker can exploit this, to gain privileged access to the system (CVE-2020-8247). 

Please refer to advisory CTX281474 for more information.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX281474");
  script_set_attribute(attribute:"solution", value:
"For versions 11.1.x, 12.1.x and 13.0.x, upgrade to 11.1.65.12, 12.1.58.15 and 13.0.64.35, or later, respectively.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8247");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_gateway");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:citrix:netscaler_application_delivery_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("citrix_netscaler_detect.nbin");
  script_require_keys("Host/NetScaler/Detected");

  exit(0);
}

version = get_kb_item_or_exit('Host/NetScaler/Version');
build = get_kb_item('Host/NetScaler/Build');

display_version = version + '-' + build;
version = version + '.' + build;
fixed_build = NULL;

if (version =~ '^11\\.1' && ver_compare(ver:build, fix:'65.12', strict:FALSE) < 0)
  fixed_build = '11.1-65.12';

if (version =~ '^12\\.1' && ver_compare(ver:build, fix:'58.15', strict:FALSE) < 0)
  fixed_build = '12.1-58.15';

if (version =~ '^13\\.0' && ver_compare(ver:build, fix:'64.35', strict:FALSE) < 0)
  fixed_build = '13.0-64.35';

if (isnull(fixed_build))
  audit(AUDIT_INST_VER_NOT_VULN, 'Citrix NetScaler', display_version);

report =
   '\n  Installed version : ' + display_version +
   '\n  Installed build   : ' + build +
   '\n  Fixed build       : ' + fixed_build +
   '\n';

security_report_v4(
  port:0,
  severity:SECURITY_HOLE,
  extra:report
);
