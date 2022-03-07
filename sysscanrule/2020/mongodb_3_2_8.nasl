#
# 
#

include("compat.inc");

if (description)
{
  script_id(122243);
  script_version("1.3");
  script_cvs_date("Date: 2019/10/31 15:18:51");

  script_cve_id(
    "CVE-2014-2917",
    "CVE-2014-3971",
    "CVE-2014-8964",
    "CVE-2015-2705",
    "CVE-2017-12926"
  );
  script_bugtraq_id(71206);

  script_name(english:"MongoDB 2.6.x < 2.6.9, 3.0.x < 3.0.14, 3.2.x < 3.2.8 mongod");
  script_summary(english:"Checks the version of MongoDB.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by a vulnerability that may
result in a denial of service or in the compromise of the server
memory integrity.");
  script_set_attribute(attribute:"description", value:
"The version of the remote MongoDB server is 2.6.x prior to 2.6.9,
is 3.0.x < 3.0.14 or is 3.2.x < 3.2.8. It is, therefore, affected by
multiple vulnerabilities.

  - A credentials disclosure vulnerability exists in the
    PEMKeyPassword, clusterPassword and Windows servicePassword. An
    unauthenticated local attacker can exploit this to get access 
    to user credentials. (CVE-2014-2917)

  - A denial of service (DoS) vulnerability exist in the
    CmdAuthenticate::_authenticateX509 function in
    db/commands/authentication_commands.cpp in mongod. An
    unauthenticated remote attacker can exploit this to cause a denial
    of service (daemon crash) by attempting authentication with an
    invalid X.509 client certificate. (CVE-2014-3971)

  - A heap-based buffer overflow condition exists in PCRE. An 
    unauthenticated remote attacker can exploit this via a crafted
    regular expression, related to an assertion that allows zero
    repeats to cause a denial of service or to cause other unspecified
    impact. (CVE-2014-8964)

  - A DoS vulnerability exists due to failure to check for missing
    values. An authenticated remote attacker can exploit this to
    cause the application to crash. The attacker needs write access
    to a database to be able to exploit this vulnerability.
    (CVE-2015-2705)

  - A breach of data integrity vulnerability exists in the WiredTiger
    storage engine. An authenticated remote attacker can exploit this
    by issuing an admin command to write statistic logs to a specific
    file and may compromise data integrity. (CVE-2017-12926)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.mongodb.org/browse/SERVER-13644");
  script_set_attribute(attribute:"see_also", value:"https://jira.mongodb.org/browse/SERVER-13753");
  script_set_attribute(attribute:"see_also", value:"https://jira.mongodb.org/browse/SERVER-17252");
  script_set_attribute(attribute:"see_also", value:"https://jira.mongodb.org/browse/SERVER-17521");
  script_set_attribute(attribute:"see_also", value:"https://jira.mongodb.org/browse/WT-2711");
  script_set_attribute(attribute:"see_also", value:"https://www.mongodb.com/alerts");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MongoDB version 2.6.9 / 3.0.14 / 3.2.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-8964");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/15");

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
  { 'min_version' : '2.6.0', 'fixed_version' : '2.6.9' },
  { 'min_version' : '3.0.0', 'fixed_version' : '3.0.14' },
  { 'min_version' : '3.2.0', 'fixed_version' : '3.2.8' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
