
##
# 
##



include('compat.inc');

if (description)
{
  script_id(152141);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/02");

  script_cve_id("CVE-2021-32719");
  script_xref(name:"IAVB", value:"2021-B-0043");

  script_name(english:"RabbitMQ < 3.8.18 XSS");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote web server is affected by denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"Pivotal RabbitMQ versions prior to 3.8.18 are affected by a cross-site scripting (XSS) vulnerability in the 
rabbitmq_federation_management plugin due to improper validation of user-supplied input before returning it to users. 
An unauthenticated, remote attacker can exploit this, by convincing a user to click a specially crafted URL, to execute
arbitrary script code in a user's browser session.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://github.com/rabbitmq/rabbitmq-server/security/advisories/GHSA-5452-hxj4-773x
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dae4cdc7");
  script_set_attribute(attribute:"see_also", value:"https://github.com/rabbitmq/rabbitmq-server/releases/tag/v3.8.18");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Pivotal RabbitMQ version 3.8.18 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32719");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pivotal_software:rabbitmq");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("rabbitmq_server_nix_installed.nbin");
  script_require_keys("installed_sw/RabbitMQ");

  exit(0);
}
include('vcf.inc');

var app_info = vcf::get_app_info(app:'RabbitMQ');

if (app_info['Managed'])
  audit(AUDIT_HOST_NOT, 'relevant to this plugin as RabbitMQ was installed by a package manager');

# Not checking if rabbitmq_federation_management plugin is enabled.
if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'RabbitMQ', app_info.version);

var constraints = [{'fixed_version' : '3.8.18'}];

vcf::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_NOTE, 
  flags:{'xss':TRUE}
);
