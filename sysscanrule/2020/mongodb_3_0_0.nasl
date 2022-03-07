#
# 
#

include("compat.inc");

if (description)
{
  script_id(126648);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/18 23:14:14");

  script_cve_id("CVE-2016-3104");
  script_bugtraq_id(94929);

  script_name(english:"MongoDB 2.4 / 2.6 Denial of Service Vulnerability");
  script_summary(english:"Checks the version of MongoDB.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the remote MongoDB server is 2.4 or 2.6. It is, therefore, affected by a denial of service vulnerability
in mongod. A remote, unauthenticated attacker can exploit this, via authenticating against a non-existent database to
cause a memory exhaustion, denying service to legitimate users.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://jira.mongodb.org/browse/SERVER-24378
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?671760f0");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch or workaround per the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-3104");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mongodb:mongodb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mongodb_detect.nasl");
  script_require_keys("Settings/ParanoidReport", "Services/mongodb");

  exit(0);
}

include('vcf.inc');

app = 'MongoDB';
port = get_service(svc:'mongodb', default:27017, exit_on_fail:TRUE);

# This issue only affects the following MongoDB versions when running with authentication under 
# MongoDB version 2.4 or MongoDB version 2.6 when running with 2.4-style users
if (report_paranoia < 2) audit(AUDIT_PARANOID);

kbVer = 'mongodb/' + port + '/Version';
app_info = vcf::get_app_info(app:app, kb_ver:kbVer, port: port);

constraints = [
  { 'min_version' : '2.4', 'max_version' : '2.4.9999', 'fixed_version' : '3.0.0' },
  { 'min_version' : '2.6', 'max_version' : '2.6.9999', 'fixed_version' : '3.0.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
