#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(121214);
  script_version("1.5");
  script_cvs_date("Date: 2019/04/02 21:54:16");

  script_cve_id(
    "CVE-2018-1000888",
    "CVE-2019-6338",
    "CVE-2019-6339"
  );
  script_bugtraq_id(
    106647,
    106664,
    106706
  );
  script_xref(name:"EDB-ID", value:"46108");

  script_name(english:"Drupal 7.x < 7.62 / 8.5.x < 8.5.9 / 8.6.x < 8.6.6 Multiple Vulnerabilities (SA-CORE-2019-001, SA-CORE-2019-002)");
  script_summary(english:"Checks the version of Drupal.");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Drupal running
on the remote web server is 7.x prior to 7.62, 8.5.x prior to
8.5.9, or 8.6.x prior to 8.6.6. It is, therefore, affected by multiple
phar handling vulnerabilities. An unauthenticated attacker could
leverage these vulnerabilities to potentially perform remote code
execution attacks and gain access in the context the web server
user.
");

  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2019-001");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/sa-core-2019-002");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/7.62");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.5.9");
  script_set_attribute(attribute:"see_also", value:"https://www.drupal.org/project/drupal/releases/8.6.6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Drupal version 7.60 / 8.5.8 / 8.6.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1000888");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
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
  { "min_version" : "8.5", "fixed_version" : "8.5.9" },
  { "min_version" : "8.6", "fixed_version" : "8.6.6" },
  { "min_version" : "7.0", "fixed_version" : "7.62" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
