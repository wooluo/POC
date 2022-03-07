#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124176);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/19  9:51:55");

  script_cve_id("CVE-2019-10909", "CVE-2019-10910", "CVE-2019-10911");

  script_name(english:"Drupal 7.x < 7.66 / 8.5.x < 8.5.15 / 8.6.x < 8.6.15 Multiple Vulnerabilities (drupal-2019-04-17)");
  script_summary(english:"Checks the version of Drupal.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running
on the remote web server is 7.x prior to 7.66, 8.5.x prior to
8.5.15, or 8.6.x prior to 8.6.15. It is, therefore, affected by
multiple vulnerabilities.

  - The jQuery project released version 3.4.0, and as part
    of that, disclosed a security vulnerability that affects
    all prior versions. As described in their release notes:
    jQuery 3.4.0 includes a fix for some unintended behavior
    when using jQuery.extend(true, {}, ...). If an
    unsanitized source object contained an enumerable
    __proto__ property, it could extend the native
    Object.prototype. This fix is included in jQuery 3.4.0,
    but patch diffs exist to patch previous jQuery versions.
    It's possible that this vulnerability is exploitable
    with some Drupal modules. As a precaution, this Drupal
    security release backports the fix to jQuery.extend(),
    without making any other changes to the jQuery version
    that is included in Drupal core (3.2.1 for Drupal 8 and
    1.4.4 for Drupal 7) or running on the site via some
    other module such as jQuery Update. (SA-CORE-2019-006)

  - This security release fixes third-party dependencies
    included in or required by Drupal core. CVE-2019-10909:
    Escape validation messages in the PHP templating engine.
    From that advisory:Validation messages were not escaped
    when using the form theme of the PHP templating engine
    which, when validation messages may contain user input,
    could result in an XSS. CVE-2019-10910: Check service
    IDs are valid. From that advisory: Service IDs derived
    from unfiltered user input could result in the execution
    of any arbitrary code, resulting in possible remote code
    execution. CVE-2019-10911: Add a separator in the
    remember me cookie hash. From that advisory: This fixes
    situations where part of an expiry time in a cookie
    could be considered part of the username, or part of the
    username could be considered part of the expiry time. An
    attacker could modify the remember me cookie and
    authenticate as a different user. This attack is only
    possible if remember me functionality is enabled and the
    two users share a password hash or the password hashes
    (e.g. UserInterface::getPassword()) are null for all
    users (which is valid if passwords are checked by an
    external system, e.g. an SSO). (CVE-2019-10909,
    CVE-2019-10910, CVE-2019-10911)

Note that GizaNE has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://blog.jquery.com/2019/04/10/jquery-3-4-0-released/");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/7.66");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.5.15");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.6.15");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/jquery_update");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2019-005");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2019-006");
  # https://symfony.com/blog/cve-2019-10909-escape-validation-messages-in-the-php-templating-engine
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://symfony.com/blog/cve-2019-10910-check-service-ids-are-valid");
  # https://symfony.com/blog/cve-2019-10911-add-a-separator-in-the-remember-me-cookie-hash
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 7.66 / 8.5.15 / 8.6.15 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10910");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/19");

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
  { "min_version" : "7", "fixed_version" : "7.66" },
  { "min_version" : "8.5", "fixed_version" : "8.5.15" },
  { "min_version" : "8.6", "fixed_version" : "8.6.15" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE, flags:{xss:TRUE});
