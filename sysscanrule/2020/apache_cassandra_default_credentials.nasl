##
# 
##

include('compat.inc');

if (description)
{
  script_id(144568);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/23");

  script_name(english:"Apache Cassandra Default Credentials");

  script_set_attribute(attribute:"synopsis", value:
"Checks if Apache Cassandra is using default credentials.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Apache Cassandra and is using default credentials. An unauthenticated, remote attacker
can exploit this to gain privileged or administrator access to the system.");
  script_set_attribute(attribute:"solution", value:
"Change the default administrative login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Default Credentials");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:cassandra");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_cassandra_remote_detection.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("installed_sw/Apache Cassandra");
  exit(0);
}

include('vcf.inc');

app = 'Apache Cassandra';

app_info = vcf::combined_get_app_info(app:app);

creds = app_info['Default Credentials'];
port = app_info['port'];

if (supplied_logins_only)
  audit(AUDIT_SUPPLIED_LOGINS_ONLY);

if(creds == 'yes') 
{
  report = '\nInstalled version : ' + app_info['version'] +
    '\nNessus was able to log into the Apache Cassandra' +
    '\nusing the default credentials : cassandra/cassandra' +
    '\n';

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}

else 
{
  audit(AUDIT_HOST_NOT, 'affected');
}
