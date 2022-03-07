#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124719);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/10  9:47:32");

  script_cve_id("CVE-2019-11358");
  script_bugtraq_id(108023);

  script_name(english:"JQuery < 3.4.0 Object Prototype Pollution Vulnerability");
  script_summary(english:"Checks the version of JQuery.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an object pollution 
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of JQuery library hosted on the remote web
server is prior to 3.4.0. It is, therefore, affected by
an object pollution vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://blog.jquery.com/2019/04/10/jquery-3-4-0-released/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JQuery version 3.4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11358");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/10");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("jquery_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Settings/ParanoidReport", "installed_sw/jquery");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("vcf.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

appname = 'jquery';
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:80);
app_info = vcf::get_app_info(app:appname, port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [{'fixed_version':'3.4.0'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
