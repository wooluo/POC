#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124698);
  script_version("1.2");
  script_cvs_date("Date: 2019/05/10 17:56:44");

  script_cve_id("CVE-2019-11831");

  script_name(english:"Drupal 7.0.x < 7.67 / 8.6.x < 8.6.16 / 8.7.x < 8.7.1 Drupal Vulnerability (SA-CORE-2019-007)");
  script_summary(english:"Checks the version of Drupal.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by a
path traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running
on the remote web server is 7.0.x prior to 7.67, 8.7.x prior to
8.6.16, or 8.7.x prior to 8.7.1. It is, therefore, affected by a
path traversal vulnerability. This security release fixes
third-party dependencies included in or required by Drupal core.
As described in TYPO3-PSA-2019-007: By-passing protection of Phar Stream
Wrapper Interceptor: In order to intercept file invocations like
file_exists or stat on compromised Phar archives the base name
has to be determined and checked before allowing to be handled by
PHP Phar stream handling. The current implementation is vulnerable
to path traversal leading to scenarios where the Phar archive to be
assessed is not the actual (compromised) file. (SA-CORE-2019-007)

Note that GizaNE has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2019-007");
  script_set_attribute(attribute:"see_also", value:"https://typo3.org/security/advisory/typo3-psa-2019-007/");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/7.67");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.6.16");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.7.1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 7.67 / 8.6.16 / 8.7.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11831");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("drupal_detect.nasl");
  script_require_keys("installed_sw/Drupal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("vcf.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:"Drupal", port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "min_version" : "7.0", "fixed_version" : "7.67" },
  { "min_version" : "8.6", "fixed_version" : "8.6.16" },
  { "min_version" : "8.7", "fixed_version" : "8.7.1" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
