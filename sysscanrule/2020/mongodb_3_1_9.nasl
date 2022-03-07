#
# 
#

include("compat.inc");

if (description)
{
  script_id(126506);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/18 23:14:14");

  script_cve_id("CVE-2015-7882");

  script_name(english:"MongoDB 3.0.x < 3.0.7 / 3.1.x < 3.1.9 Authentication Bypass");
  script_summary(english:"Checks the version of MongoDB.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by an authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the remote MongoDB server is 3.0.x prior to 3.0.7, 3.1.x prior to 3.1.9. It is, therefore, affected by
an unspecified flaw in LDAP authentication. An attacker may exploit this to gain unauthorized access to a MongoDB
instance or cluster.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://jira.mongodb.org/browse/SERVER-20691
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5e10402c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MongoDB version 3.0.7 / 3.1.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7882");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mongodb:mongodb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mongodb_detect.nasl");
  script_require_keys("Services/mongodb");

  exit(0);
}

include('vcf.inc');

# Only deployments using LDAP authentication are affected by this vulnerability.
# The Community edition of MongoDB is not affected by this vulnerability.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = 'MongoDB';
port = get_service(svc:'mongodb', default:27017, exit_on_fail:TRUE);
kbVer = 'mongodb/' + port + '/Version';

app_info = vcf::get_app_info(app:app, kb_ver:kbVer, port: port);

constraints = [
  { 'min_version' : '3.0.0', 'fixed_version' : '3.0.7' },
  { 'min_version' : '3.1.0', 'fixed_version' : '3.1.9' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
