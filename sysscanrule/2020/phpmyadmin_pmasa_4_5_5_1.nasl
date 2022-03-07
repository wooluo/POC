##
# 
##

include('compat.inc');

if (description)
{
  script_id(143489);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/08");

  script_cve_id(
    "CVE-2016-2559",
    "CVE-2016-2560",
    "CVE-2016-2561",
    "CVE-2016-2562"
  );
  script_bugtraq_id(
    83704,
    83711,
    83717,
    83718
  );

  script_name(english:"phpMyAdmin 4.0.x < 4.0.10.15 / 4.4.x < 4.4.15.5 / 4.5.x < 4.5.5.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the phpMyAdmin application hosted on the remote web server is 4.0.x prior to
4.0.10.15, 4.4.x prior to 4.4.15.5, or 4.5.x prior to 4.5.5.1. It is, therefore, affected by multiple vulnerabilities.

  - Cross-site scripting (XSS) vulnerability in the format function in libraries/sql-
    parser/src/Utils/Error.php in the SQL parser in phpMyAdmin 4.5.x before 4.5.5.1 allows remote
    authenticated users to inject arbitrary web script or HTML via a crafted query. (CVE-2016-2559)

  - Multiple cross-site scripting (XSS) vulnerabilities in phpMyAdmin 4.0.x before 4.0.10.15, 4.4.x before
    4.4.15.5, and 4.5.x before 4.5.5.1 allow remote attackers to inject arbitrary web script or HTML via (1) a
    crafted Host HTTP header, related to libraries/Config.class.php; (2) crafted JSON data, related to
    file_echo.php; (3) a crafted SQL query, related to js/functions.js; (4) the initial parameter to
    libraries/server_privileges.lib.php in the user accounts page; or (5) the it parameter to
    libraries/controllers/TableSearchController.class.php in the zoom search page. (CVE-2016-2560)

  - Multiple cross-site scripting (XSS) vulnerabilities in phpMyAdmin 4.4.x before 4.4.15.5 and 4.5.x before
    4.5.5.1 allow remote authenticated users to inject arbitrary web script or HTML via (1) normalization.php
    or (2) js/normalization.js in the database normalization page, (3)
    templates/database/structure/sortable_header.phtml in the database structure page, or (4) the pos
    parameter to db_central_columns.php in the central columns page. (CVE-2016-2561)

  - The checkHTTP function in libraries/Config.class.php in phpMyAdmin 4.5.x before 4.5.5.1 does not verify
    X.509 certificates from api.github.com SSL servers, which allows man-in-the-middle attackers to spoof
    these servers and obtain sensitive information via a crafted certificate. (CVE-2016-2562)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-10/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-11/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-12/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-13/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin version 4.0.10.15 / 4.4.15.5 / 4.5.5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2562");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(79, 295, 661);

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/07");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_require_keys("www/PHP", "installed_sw/phpMyAdmin", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:'phpMyAdmin', port:port, webapp:TRUE);

constraints = [
  { 'min_version' : '4.0.0', 'fixed_version' : '4.0.10.15' },
  { 'min_version' : '4.4.0', 'fixed_version' : '4.4.15.5' },
  { 'min_version' : '4.5.0', 'fixed_version' : '4.5.5.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
