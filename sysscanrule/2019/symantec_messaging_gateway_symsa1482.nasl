#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125373);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/18 15:47:53");

  script_cve_id("CVE-2019-9699");
  script_bugtraq_id(108303);

  script_name(english:"Symantec Messaging Gateway 10.x < 10.7.0 Information Disclosure Vulnerability (SYMSA1482)");
  script_summary(english:"Checks the Symantec Messaging Gateway version number.");

  script_set_attribute(attribute:"synopsis", value:
"A messaging security application running on the remote host is
affected by an information disclosure vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Symantec Messaging
Gateway (SMG) running on the remote host is 10.x prior to 10.7.0.
It is, therefore, affected by information disclosure vulnerability as described 
in the vendor advisory.

Note that GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://support.symantec.com/en_US/article.SYMSA1482.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Messaging Gateway (SMG) version 10.7.0 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:M/C:C/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9699");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:messaging_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("symantec_messaging_gateway_detect.nasl");
  script_require_keys("www/sym_msg_gateway");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

appname = 'sym_msg_gateway';
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:443);
app_info = vcf::get_app_info(app:appname, port:port, webapp:true);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '10.0.0', 'fixed_version' : '10.7.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
