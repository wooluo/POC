#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122589);
  script_version("1.1");
  script_cvs_date("Date: 2019/03/04 14:05:42");

  script_cve_id("CVE-2019-7608", "CVE-2019-7609", "CVE-2019-7610");
  script_bugtraq_id(107148);

  script_name(english:"Kibana ESA-2019-01, ESA-2019-02, ESA-2019-03");
  script_summary(english:"Checks the version of Kibana.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a Java application that is vulnerable.");
  script_set_attribute(attribute:"description", value:
"Kibana versions before 5.6.15 and 6.6.1 have the following
vulnerabilities:

  - A cross-site scripting (XSS) vulnerability that could
    allow an attacker to obtain sensitive information from
    or perform destructive actions on behalf of other
    Kibana users. (CVE-2019-7608)

  - An arbitrary code execution flaw in the Timelion
    visualizer. An attacker with access to the Timelion
    application could send a request that will attempt to
    execute javascript code. This could possibly lead to an
    attacker executing arbitrary commands with permissions
    of the Kibana process on the host system. (CVE-2019-7609)

  - An arbitrary code execution flaw in the security audit
    logger. If a Kibana instance has the setting
    xpack.security.audit.enabled set to true, an attacker
    could send a request that will attempt to execute
    javascript code. This could possibly lead to an attacker
    executing arbitrary commands with permissions of the
    Kibana process on the host system. (CVE-2019-7610)");
  script_set_attribute(attribute:"see_also", value:"https://www.elastic.co/community/security");
  script_set_attribute(attribute:"solution", value:
"Users should upgrade to Kibana version 5.6.15 or 6.6.1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7609");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:elasticsearch:kibana");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("kibana_web_detect.nbin");
  script_require_keys("installed_sw/Kibana");
  script_require_ports("Services/www", 5601);

  exit(0);
}

include("audit.inc");
include("http.inc");
include("vcf.inc");

app = "Kibana";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:5601);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

constraints = [
  { "min_version" : "5.0.0", "fixed_version" : "5.6.15" },
  { "min_version" : "6.0.0", "fixed_version" : "6.6.1" }
];

flags = { 'xss':TRUE };

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:flags);
