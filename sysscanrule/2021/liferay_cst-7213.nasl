##
# 
##

include('compat.inc');

if (description)
{
  script_id(151011);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/25");

  script_cve_id("CVE-2020-15842");
  script_xref(name:"IAVA", value:"2021-A-0296");

  script_name(english:"Liferay Portal Insecure Deserialization (CST-7213)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by an insecure deserialization vulnerability");
  script_set_attribute(attribute:"description", value:
"Liferay Portal before 7.3.0, 7.1 before fix pack 17, and 7.2 before fix pack 5, allows man-in-the-middle
attackers to execute arbitrary code via crafted serialized payloads, because of insecure deserialization.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://portal.liferay.dev/learn/security/known-vulnerabilities/-/asset_publisher/HbL5mxmVrnXW/content/id/119317427
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e208402f");
  script_set_attribute(attribute:"solution", value:
"Refer to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-15842");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:liferay:portal");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("liferay_detect.nasl");
  script_require_keys("installed_sw/liferay_portal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var app = 'liferay_portal';
var port = get_http_port(default:8080);

var app_info = vcf::get_app_info(app:app, webapp:TRUE, port:port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

var constraints = [
  { 'fixed_version' : '7.3.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
