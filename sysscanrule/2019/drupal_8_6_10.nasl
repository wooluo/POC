#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(122349);
  script_version("1.8");
  script_cvs_date("Date: 2019/08/23 10:01:45");

  script_cve_id("CVE-2019-6340");

  script_name(english:"Drupal 8.5.x < 8.5.11 / 8.6.x < 8.6.10 Remote Code Execution (SA-CORE-2019-003)");
  script_summary(english:"Checks the version of Drupal.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by
a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal
running on the remote web server is 8.5.x prior to 8.5.11, or 8.6.x
prior to 8.6.10. It is, therefore, affected by a remote code
execution vulnerability due to improper sanitization of data from
non-form sources.");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2019-003");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.5.11");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.6.10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 8.5.11 / 8.6.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6340");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Drupal RESTful Web Services unserialize() RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
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

app_info = vcf::get_app_info(app:"Drupal", port:port, webapp:true);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "min_version" : "8.5", "fixed_version" : "8.5.11" },
  { "min_version" : "8.6", "fixed_version" : "8.6.10" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
