
##
# 
##



include('compat.inc');

if (description)
{
  script_id(150154);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/07");

  script_cve_id("CVE-2021-23017");
  script_xref(name:"IAVB", value:"2021-B-0031");

  script_name(english:"nginx 0.6.x < 1.20.1 1-Byte Memory Overwrite RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its Sever response header, the installed version of nginx is 0.6.18 prior to 1.20.1. It is, therefore,
affected by a remote code execution vulnerability. A security issue in nginx resolver was identified, which might allow 
an unautheticated remote attacker to cause 1-byte memory overwrite by using a specially crafted DNS response, resulting
in worker process crash or, potentially, in arbitrary code execution.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://mailman.nginx.org/pipermail/nginx-announce/2021/000300.html");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/download/patch.2021.resolver.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to nginx 1.20.1 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-23017");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(193);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nginx:nginx");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nginx_detect.nasl", "nginx_nix_installed.nbin");
  script_require_keys("installed_sw/nginx");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var appname = 'nginx';
get_install_count(app_name:appname, exit_if_zero:TRUE);

var app_info = vcf::combined_get_app_info(app:appname);
vcf::check_granularity(app_info:app_info, sig_segments:3);

if (empty_or_null(app_info['Detection Method']) && report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  { 'min_version' : '0.6.18', 'fixed_version' : '1.20.1', 'fixed_display': '1.20.1 / 1.21.0' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
