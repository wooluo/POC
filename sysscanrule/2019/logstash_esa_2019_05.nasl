#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122977);
  script_version("1.1");
  script_cvs_date("Date: 2019/03/20 13:27:46");

  script_cve_id("CVE-2019-7612");

  script_name(english:"Logstash ESA-2019-05");
  script_summary(english:"Checks the version of Logstash.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a Java application that is vulnerable.");
  script_set_attribute(attribute:"description", value:
"A sensitive data disclosure flaw was found in the way Logstash logs
malformed URLs. If a malformed URL is specified as part of the
Logstash configuration, the credentials for the URL could be
inadvertently logged as part of the error message.");
  script_set_attribute(attribute:"see_also", value:"https://www.elastic.co/community/security");
  script_set_attribute(attribute:"solution", value:
"Users should upgrade to Logstash version 5.6.15 or 6.6.1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7612");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:elasticsearch:logstash");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("logstash_api_detect.nbin");
  script_require_keys("installed_sw/Logstash");
  script_require_ports("Services/www", 9600);

  exit(0);
}

include("audit.inc");
include("http.inc");
include("vcf.inc");

app = "Logstash";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:9600);

app_info = vcf::get_app_info(app:app, port:port, webapp:TRUE);

constraints = [
  { "min_version" : "5.0.0", "fixed_version" : "5.6.15" },
  { "min_version" : "6.0.0", "fixed_version" : "6.6.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
