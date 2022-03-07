#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(123006);
  script_version("1.3");
  script_cvs_date("Date: 2019/03/29  7:43:23");

  script_cve_id("CVE-2019-6341");
  script_xref(name:"IAVA", value:"2019-A-0092");

  script_name(english:"Drupal 7.x < 7.65 / 8.5.x < 8.5.14 / 8.6.x < 8.6.13 XSS (SA-CORE-2019-004)");
  script_summary(english:"Checks the version of Drupal.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by
a cross site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal
running on the remote web server is 7.x prior to 7.65, 8.5.x prior to
8.5.14, or 8.6.x prior to 8.6.13. It is, therefore, affected by a
cross site scripting (XSS) vulnerability in the File module/subsystem
due to improper sanitization of data in uploaded files.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2019-004");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/7.65");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.5.14");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.6.13");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 7.65 / 8.5.14 / 8.6.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6341");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

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

app_info = vcf::get_app_info(app:"Drupal", port:port, webapp:true);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "min_version" : "7.0", "fixed_version" : "7.65" },
  { "min_version" : "8.5", "fixed_version" : "8.5.14" },
  { "min_version" : "8.6", "fixed_version" : "8.6.13" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE, flags:{xss:TRUE});
