#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125896);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/14 15:47:37");

  script_cve_id("CVE-2019-4055");
  script_bugtraq_id(108027);
  script_xref(name:"IAVA", value:"2019-A-0191");

  script_name(english:"IBM MQ 8.0.0.x < 8.0.0.11 / 9.0.0.x < 9.0.0.6 / 9.1.0.x < 9.1.0.2 / 9.1.1 TLS Key Renegotiation DoS");
  script_summary(english:"Checks the version of IBM MQ.");

  script_set_attribute(attribute:"synopsis", value:
"A message queuing service installed on the remote host is affected
by a denial-of-service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM MQ server installed
on the remote host is 8.0.0.x prior to 8.0.0.11 LTS, 9.0.0.x prior to
9.0.0.6 LTS, 9.1.0.x prior to 9.1.0.2 LTS, or 9.1.1 CD and is therefore
affected by a denial-of-service vulnerability in the IBM MQ Queue
Manager due to a weakness in the TLS key renegotiation functions. An
unauthenticated, remote attacker could exploit this vulnerability to
impact the availability of the service.");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=ibm10870484");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM MQ 8.0.0.11, 9.0.0.6, 9.1.0.2, 9.1.2 or later as per
the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-4055");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_mq");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_mq_installed.nasl");
  script_require_keys("installed_sw/IBM WebSphere MQ");

  exit(0);
}

include('vcf.inc');


app = 'IBM WebSphere MQ';
app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '8.0.0', 'fixed_version' : '8.0.0.11' },
  { 'min_version' : '9.0.0', 'fixed_version' : '9.0.0.6' },
  { 'min_version' : '9.1.0', 'fixed_version' : '9.1.0.2' },
  { 'min_version' : '9.1.1', 'fixed_version' : '9.1.2.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
