#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127907);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/16 13:14:01");

  script_cve_id("CVE-2019-9511", "CVE-2019-9513", "CVE-2019-9516");

  script_name(english:"nginx 1.9.5 < 1.16.1 / 1.17.x < 1.17.3 Multiple Vulnerabilties");
  script_summary(english:"Checks the version of nginx");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by multiple denial of service vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its Server response header, the installed version of nginx is 1.9.5 prior to 1.16.1 or 1.17.x prior to
1.17.3. It is, therefore, affected by multiple denial of service vulnerabilities :

  - A denial of service vulnerability exists in the HTTP/2 protocol stack due to improper handling of exceptional
    conditions. An unauthenticated, remote attacker can exploit this, by manipulating the window size and stream
    priority of a large data request, to cause a denial of service condition. (CVE-2019-9511)

  - A denial of service vulnerability exists in the HTTP/2 protocol stack due to improper handling of exceptional
    conditions. An unauthenticated, remote attacker can exploit this, by creating multiple request streams and
    continually shuffling the priority of the streams, to cause a denial of service condition. (CVE-2019-9513)

  - A denial of service vulnerability exists in the HTTP/2 protocol stack due to improper handling of exceptional
    conditions. An unauthenticated, remote attacker can exploit this, by sending a stream of headers with a zero length
    header name and zero length header value, to cause a denial of service condition. (CVE-2019-9516)
");
  # https://www.nginx.com/blog/nginx-updates-mitigate-august-2019-http-2-vulnerabilities/
  script_set_attribute(attribute:"see_also", value:"");
  # https://github.com/Netflix/security-bulletins/blob/master/advisories/third-party/2019-002.md
  script_set_attribute(attribute:"see_also", value:"");
  # http://nginx.org/en/security_advisories.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to nginx version 1.16.1 / 1.17.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9511");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:igor_sysoev:nginx");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("nginx_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/nginx");
  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("http.inc");
include("vcf.inc");

appname = "nginx";
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:80);
app_info = vcf::get_app_info(app:appname, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  {"min_version" : "1.9.5", "fixed_version" : "1.16.0", "fixed_display" : "1.16.1 / 1.17.3"},
  {"min_version" : "1.16.0", "fixed_version" : "1.16.1"},
  {"min_version" : "1.17.0", "fixed_version" : "1.17.3"}
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
