#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124335);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/26 14:23:41");

  script_cve_id("CVE-2019-7401");
  script_bugtraq_id(106956);
  script_xref(name:"IAVB", value:"2019-B-0028");

  script_name(english:"NGINX Unit 0.x > 0.3 / 1.x < 1.7.1 Heap Buffer Overflow (CVE-2019-7401)");
  script_summary(english:"Checks the version of nginx.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a heap buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to the self-reported version in its response header, the
version of NGINX Unit hosted on the remote web server is 0.x later
than 0.3 or 1.x prior to 1.7.1. It is, therefore, affected by a heap
buffer overflow vulnerability in the router process. An
unauthenticated, remote attacker can exploit this, via a specially
crafted request, to cause a denial of service condition or the
execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://mailman.nginx.org/pipermail/unit/2019-February/000113.html");
  script_set_attribute(attribute:"see_also", value:"http://unit.nginx.org/CHANGES.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NGINX Unit version 1.7.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7401");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nginx:unit");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("nginx_unit_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/NGINX Unit");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("vcf.inc");

appname = "NGINX Unit";
get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_http_port(default:80);
app_info = vcf::get_app_info(app:appname, port:port, webapp:TRUE);

constraints = [
  {"min_version":"0.3", "fixed_version":"1.7.1"}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
