include("compat.inc");

if (description)
{
  script_id(118956);
  script_version("1.5");
  script_cvs_date("Date: 2019/04/26 11:34:29");

  script_cve_id(
    "CVE-2018-16843",
    "CVE-2018-16844",
    "CVE-2018-16845"
  );
  script_bugtraq_id(105868);

  script_name(english:"nginx 1.x < 1.14.1 / 1.15.x < 1.15.6 Multiple Vulnerabilties");
  script_summary(english:"Checks version of nginx");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(
    attribute:"description",
    value:
"According to its Server response header, the installed version of nginx
is 1.x prior to 1.14.1 or 1.15.x prior to 1.15.6. It is,  therefore,
affected by the following issues :

  - An unspecified error exists related to the module
    'ngx_http_v2_module' that allows excessive memory usage.
    (CVE-2016-16843)

  - An unspecified error exists related to the module
    'ngx_http_v2_module' that allows excessive CPU usage.
    (CVE-2016-16844)

  - An unspecified error exists related to the module
    'ngx_http_mp4_module' that allows worker process
    crashes or memory disclosure. (CVE-2016-16845)");
  script_set_attribute(attribute:"see_also", value:"http://nginx.org/en/security_advisories.html");
  script_set_attribute(attribute:"see_also", value:"http://mailman.nginx.org/pipermail/nginx-announce/2018/000220.html");
  script_set_attribute(attribute:"see_also", value:"http://mailman.nginx.org/pipermail/nginx-announce/2018/000221.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to nginx 1.14.1 / 1.15.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"composite vector of multiple vulnerabilities in the given version");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:igor_sysoev:nginx");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by WebRAY, Inc.");

  script_dependencies("nginx_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Settings/ParanoidReport", "installed_sw/nginx");
  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("http.inc");
include("vcf.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

appname = "nginx";
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:80);
app_info = vcf::get_app_info(app:appname, port:port, webapp:TRUE);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  {"fixed_version":"1.14.1", "min_version" : "1.0.7", "fixed_display": "1.14.1"},
  {"fixed_version":"1.15.6", "min_version" : "1.15.0", "fixed_display": "1.15.6"}
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
