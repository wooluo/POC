##
# 
##

include('compat.inc');

if (description)
{
  script_id(143532);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/08");

  script_cve_id(
    "CVE-2016-9847",
    "CVE-2016-9848",
    "CVE-2016-9849",
    "CVE-2016-9850",
    "CVE-2016-9851",
    "CVE-2016-9852",
    "CVE-2016-9853",
    "CVE-2016-9854",
    "CVE-2016-9855",
    "CVE-2016-9856",
    "CVE-2016-9857",
    "CVE-2016-9858",
    "CVE-2016-9859",
    "CVE-2016-9860",
    "CVE-2016-9861",
    "CVE-2016-9864",
    "CVE-2016-9865",
    "CVE-2016-9866"
  );
  script_bugtraq_id(
    94521,
    94523,
    94524,
    94525,
    94527,
    94529,
    94530,
    94531,
    94533,
    94534,
    94535,
    94536
  );

  script_name(english:"phpMyAdmin 4.0.x < 4.0.10.18 / 4.4.x < 4.4.15.9 / 4.6.x < 4.6.5 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the phpMyAdmin application hosted on the remote web server is 4.0.x prior to
4.0.10.18, 4.4.x prior to 4.4.15.9, or 4.6.x prior to 4.6.5. It is, therefore, affected by multiple vulnerabilities.

  - An issue was discovered in phpMyAdmin. When the user does not specify a blowfish_secret key for encrypting
    cookies, phpMyAdmin generates one at runtime. A vulnerability was reported where the way this value is
    created uses a weak algorithm. This could allow an attacker to determine the user's blowfish_secret and
    potentially decrypt their cookies. All 4.6.x versions (prior to 4.6.5), 4.4.x versions (prior to
    4.4.15.9), and 4.0.x versions (prior to 4.0.10.18) are affected. (CVE-2016-9847)

  - An issue was discovered in phpMyAdmin. phpinfo (phpinfo.php) shows PHP information including values of
    HttpOnly cookies. All 4.6.x versions (prior to 4.6.5), 4.4.x versions (prior to 4.4.15.9), and 4.0.x
    versions (prior to 4.0.10.18) are affected. (CVE-2016-9848)

  - An issue was discovered in phpMyAdmin. It is possible to bypass AllowRoot restriction
    ($cfg['Servers'][$i]['AllowRoot']) and deny rules for username by using Null Byte in the username. All
    4.6.x versions (prior to 4.6.5), 4.4.x versions (prior to 4.4.15.9), and 4.0.x versions (prior to
    4.0.10.18) are affected. (CVE-2016-9849)

  - An issue was discovered in phpMyAdmin. Username matching for the allow/deny rules may result in wrong
    matches and detection of the username in the rule due to non-constant execution time. All 4.6.x versions
    (prior to 4.6.5), 4.4.x versions (prior to 4.4.15.9), and 4.0.x versions (prior to 4.0.10.18) are
    affected. (CVE-2016-9850)

  - An issue was discovered in phpMyAdmin. With a crafted request parameter value it is possible to bypass the
    logout timeout. All 4.6.x versions (prior to 4.6.5), and 4.4.x versions (prior to 4.4.15.9) are affected.
    (CVE-2016-9851)

  - An issue was discovered in phpMyAdmin. By calling some scripts that are part of phpMyAdmin in an
    unexpected way, it is possible to trigger phpMyAdmin to display a PHP error message which contains the
    full path of the directory where phpMyAdmin is installed. During an execution timeout in the export
    functionality, the errors containing the full path of the directory of phpMyAdmin are written to the
    export file. All 4.6.x versions (prior to 4.6.5), and 4.4.x versions (prior to 4.4.15.9) are affected.
    This CVE is for the curl wrapper issue. (CVE-2016-9852)

  - An issue was discovered in phpMyAdmin. By calling some scripts that are part of phpMyAdmin in an
    unexpected way, it is possible to trigger phpMyAdmin to display a PHP error message which contains the
    full path of the directory where phpMyAdmin is installed. During an execution timeout in the export
    functionality, the errors containing the full path of the directory of phpMyAdmin are written to the
    export file. All 4.6.x versions (prior to 4.6.5), and 4.4.x versions (prior to 4.4.15.9) are affected.
    This CVE is for the fopen wrapper issue. (CVE-2016-9853)

  - An issue was discovered in phpMyAdmin. By calling some scripts that are part of phpMyAdmin in an
    unexpected way, it is possible to trigger phpMyAdmin to display a PHP error message which contains the
    full path of the directory where phpMyAdmin is installed. During an execution timeout in the export
    functionality, the errors containing the full path of the directory of phpMyAdmin are written to the
    export file. All 4.6.x versions (prior to 4.6.5), and 4.4.x versions (prior to 4.4.15.9) are affected.
    This CVE is for the json_decode issue. (CVE-2016-9854)

  - An issue was discovered in phpMyAdmin. By calling some scripts that are part of phpMyAdmin in an
    unexpected way, it is possible to trigger phpMyAdmin to display a PHP error message which contains the
    full path of the directory where phpMyAdmin is installed. During an execution timeout in the export
    functionality, the errors containing the full path of the directory of phpMyAdmin are written to the
    export file. All 4.6.x versions (prior to 4.6.5), and 4.4.x versions (prior to 4.4.15.9) are affected.
    This CVE is for the PMA_shutdownDuringExport issue. (CVE-2016-9855)

  - An XSS issue was discovered in phpMyAdmin because of an improper fix for CVE-2016-2559 in PMASA-2016-10.
    This issue is resolved by using a copy of a hash to avoid a race condition. All 4.6.x versions (prior to
    4.6.5), 4.4.x versions (prior to 4.4.15.9), and 4.0.x versions (prior to 4.0.10.18) are affected.
    (CVE-2016-9856)

  - An issue was discovered in phpMyAdmin. XSS is possible because of a weakness in a regular expression used
    in some JavaScript processing. All 4.6.x versions (prior to 4.6.5), 4.4.x versions (prior to 4.4.15.9),
    and 4.0.x versions (prior to 4.0.10.18) are affected. (CVE-2016-9857)

  - An issue was discovered in phpMyAdmin. With a crafted request parameter value it is possible to initiate a
    denial of service attack in saved searches feature. All 4.6.x versions (prior to 4.6.5), 4.4.x versions
    (prior to 4.4.15.9), and 4.0.x versions (prior to 4.0.10.18) are affected. (CVE-2016-9858)

  - An issue was discovered in phpMyAdmin. With a crafted request parameter value it is possible to initiate a
    denial of service attack in import feature. All 4.6.x versions (prior to 4.6.5), 4.4.x versions (prior to
    4.4.15.9), and 4.0.x versions (prior to 4.0.10.18) are affected. (CVE-2016-9859)

  - An issue was discovered in phpMyAdmin. An unauthenticated user can execute a denial of service attack when
    phpMyAdmin is running with $cfg['AllowArbitraryServer']=true. All 4.6.x versions (prior to 4.6.5), 4.4.x
    versions (prior to 4.4.15.9), and 4.0.x versions (prior to 4.0.10.18) are affected. (CVE-2016-9860)

  - An issue was discovered in phpMyAdmin. Due to the limitation in URL matching, it was possible to bypass
    the URL white-list protection. All 4.6.x versions (prior to 4.6.5), 4.4.x versions (prior to 4.4.15.9),
    and 4.0.x versions (prior to 4.0.10.18) are affected. (CVE-2016-9861)

  - An issue was discovered in phpMyAdmin. With a crafted username or a table name, it was possible to inject
    SQL statements in the tracking functionality that would run with the privileges of the control user. This
    gives read and write access to the tables of the configuration storage database, and if the control user
    has the necessary privileges, read access to some tables of the MySQL database. All 4.6.x versions (prior
    to 4.6.5), 4.4.x versions (prior to 4.4.15.9), and 4.0.x versions (prior to 4.0.10.18) are affected.
    (CVE-2016-9864)

  - An issue was discovered in phpMyAdmin. Due to a bug in serialized string parsing, it was possible to
    bypass the protection offered by PMA_safeUnserialize() function. All 4.6.x versions (prior to 4.6.5),
    4.4.x versions (prior to 4.4.15.9), and 4.0.x versions (prior to 4.0.10.18) are affected. (CVE-2016-9865)

  - An issue was discovered in phpMyAdmin. When the arg_separator is different from its default & value, the
    CSRF token was not properly stripped from the return URL of the preference import action. All 4.6.x
    versions (prior to 4.6.5), 4.4.x versions (prior to 4.4.15.9), and 4.0.x versions (prior to 4.0.10.18) are
    affected. (CVE-2016-9866)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-58/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-59/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-60/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-61/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-62/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-63/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-64/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-65/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-66/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-69/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-70/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2016-71/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpMyAdmin version 4.0.10.18 / 4.4.15.9 / 4.6.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9865");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20, 89, 352, 400, 601, 661);

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/25");
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
  { 'min_version' : '4.0.0', 'fixed_version' : '4.0.10.18' },
  { 'min_version' : '4.4.0', 'fixed_version' : '4.4.15.9' },
  { 'min_version' : '4.6.0', 'fixed_version' : '4.6.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{sqli:TRUE, xss:TRUE, xsrf:TRUE});
