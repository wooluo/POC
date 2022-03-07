##
# 
##

include('compat.inc');

if (description)
{
  script_id(149704);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/19");

  script_cve_id("CVE-2021-22116");

  script_name(english:"Pivotal RabbitMQ 3.8.x < 3.8.16 DoS");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote web server is affected by denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"Pivotal RabbitMQ versions 3.8.x prior to 3.8.16 are affected by a denial of service (DoS) vulnerability due to improper
input validation. A remote attacker can exploit this by sending malicious AMQP messages in order to cause a crash.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://tanzu.vmware.com/security/cve-2021-22116");
  script_set_attribute(attribute:"see_also", value:"https://github.com/rabbitmq/rabbitmq-server/releases/tag/v3.8.15");
  script_set_attribute(attribute:"see_also", value:"https://github.com/rabbitmq/rabbitmq-server/releases/tag/v3.8.16");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Pivotal RabbitMQ version 3.8.16 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22116");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pivotal_software:rabbitmq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("rabbitmq_server_nix_installed.nbin");
  script_require_keys("installed_sw/RabbitMQ");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'RabbitMQ', port:port);

if (app_info['Managed'])
  audit(AUDIT_HOST_NOT, 'relevant to this plugin as RabbitMQ was installed by a package manager');

# Not checking for AMQP 1.0 plugin enabled
if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'RabbitMQ', app_info.version);

vcf::check_granularity(app_info:app_info, sig_segments:2);

var constraints = [
  {'min_version' : '3.8.0',  'fixed_version' : '3.8.16'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
