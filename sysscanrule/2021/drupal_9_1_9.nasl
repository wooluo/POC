
##
# 
##


include('compat.inc');

if (description)
{
  script_id(149999);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/27");

  script_name(english:"Drupal 8.9.x < 8.9.16 / 9.x < 9.0.14 / 9.1.x < 9.1.9 Drupal Vulnerability (SA-CORE-2021-003) ");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running on the remote web server is 8.9.x prior to
8.9.16, 9.x prior to 9.0.14, or 9.1.x prior to 9.1.9. It is, therefore, affected by a vulnerability.

  - Drupal core uses the third-party CKEditor library. This library has an error in parsing HTML that could
    lead to an XSS attack. CKEditor 4.16.1 and later include the fix. Users of the CKEditor library via means
    other than Drupal core should update their 3rd party code (e.g. the WYSIWYG module for Drupal 7). The
    Drupal Security Team policy is not to alert for issues affecting 3rd party libraries unless those are
    shipped with Drupal core. See DRUPAL-SA-PSA-2016-004 for more details. This issue is mitigated by the fact
    that it only affects sites with CKEditor enabled. (SA-CORE-2021-003)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2021-003");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.9.16");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.0.14");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/9.1.9");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/psa-2016-004");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 8.9.16 / 9.0.14 / 9.1.9 or later.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("drupal_detect.nasl");
  script_require_keys("installed_sw/Drupal", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, php:TRUE);

app_info = vcf::get_app_info(app:'Drupal', port:port, webapp:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { 'min_version' : '8.9', 'fixed_version' : '8.9.16' },
  { 'min_version' : '9.0', 'fixed_version' : '9.0.14' },
  { 'min_version' : '9.1', 'fixed_version' : '9.1.9' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
