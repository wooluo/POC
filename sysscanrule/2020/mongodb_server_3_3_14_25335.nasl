#
# 
#

include('compat.inc');

if (description)
{
  script_id(135921);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/24");

  script_cve_id("CVE-2016-6494");
  script_bugtraq_id(92204);

  script_name(english:"MongoDB 2.x, 3.0.x < 3.0.15, 3.1.x < 3.2.14, 3.3.x < 3.3.14 Mongo Shell Information Disclosure Vulnerability (SERVER-25335)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by an information disclosure  vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the remote MongoDB server is 2.x, 3.x < 3.0.15, 3.2.x < 3.2.14, 3.3.x < 3.3.14. It is, therefore,
affected by an information disclosure in mongo shell due to the MongoDB client having world-readable permissions on 
.dbshell history files. An unauthenticated, local attacker can exploit this by reading these files to disclose 
potentially sensitive information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.mongodb.com/alerts
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fabe3381");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MongoDB version 3.0.15, 3.2.14, 3.3.14, 3.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6494");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mongodb:mongodb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mongodb_detect.nasl");
  script_require_keys("Services/mongodb");

  exit(0);
}

include('vcf.inc');

app = 'MongoDB';
port = get_service(svc:'mongodb', default:27017, exit_on_fail:TRUE);
kbVer = 'mongodb/' + port + '/Version';

app_info = vcf::get_app_info(app:app, kb_ver:kbVer, port: port);

constraints = [
  { 'min_version' : '2.0', 'max_version' : '3.0', 'fixed_display' : '3.0.15, 3.2.14, 3.3.14, 3.4 or later' },
  { 'min_version' : '3.0.0', 'fixed_version' : '3.0.15' },
  { 'min_version' : '3.1.0', 'fixed_version' : '3.2.14' },
  { 'min_version' : '3.3.0', 'fixed_version' : '3.3.14' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
