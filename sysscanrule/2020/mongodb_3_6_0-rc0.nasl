#
# 
#

include("compat.inc");

if (description)
{
  script_id(122363);
  script_version("1.2");
  script_cvs_date("Date: 2019/10/31 15:18:51");

  script_cve_id("CVE-2017-15535");
  script_bugtraq_id(101689);

  script_name(english:"MongoDB 3.4.x < 3.4.10 / 3.5.x < 3.6.0-rc0 mongod");
  script_summary(english:"Checks the version of MongoDB.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a vulnerability that may
result in a denial of service or in the compromise of the server
memory integrity.");
  script_set_attribute(attribute:"description", value:
"The version of the remote MongoDB server is 3.4.x prior to 3.4.10 /
3.5.x prior to 3.6.0-rc0. It is, therefore, affected by a denial of
service vulnerability in mongod networkMessageCompressors due to an
implementation error. A remote, unauthenticated attacker can exploit
this, to cause a denial of service or to modify server memory.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.mongodb.org/browse/SERVER-31273");
  script_set_attribute(attribute:"see_also", value:"https://www.mongodb.com/alerts");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MongoDB version 3.4.10 / 3.6.0-rc0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15535");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/21");

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

app = 'MongoDB';
port = get_service(svc:'mongodb', default:27017, exit_on_fail:TRUE);
kbVer = 'mongodb/' + port + '/Version';

app_info = vcf::get_app_info(app:app, kb_ver:kbVer, port: port);

constraints = [
  { 'min_version' : '3.4.0', 'fixed_version' : '3.4.10' },
  { 'min_version' : '3.5.0', 'fixed_version' : '3.6.0-rc0'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
