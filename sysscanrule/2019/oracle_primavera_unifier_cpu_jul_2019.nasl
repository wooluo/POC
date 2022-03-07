#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126829);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/19 16:59:43");

  script_cve_id(
    "CVE-2017-3164",
    "CVE-2015-9251",
    "CVE-2018-17197",
    "CVE-2019-0192"
  );
  script_bugtraq_id(
    105658,
    106293,
    107026,
    107318
  );

  script_name(english:"Oracle Primavera Unifier Multiple Vulnerabilities (Jul 2019 CPU)");
  script_summary(english:"Checks the version of Oracle Primavera Unifier.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Oracle Primavera
Unifier installation running on the remote web server is 15.x or 16.x 
prior to 16.2.15.9 or 17.7.x prior to 17.12.11 or 18.x prior to 18.8.11. It is, 
therefore, affected by multiple vulnerabilities:

  - A deserialization vulnerability exists in the Apache Solr
    subcomponent of Primavera Unifier. An unauthenticated, 
    remote attacker can exploit this, via a specially crafted
    request to the Solr Config API, to execute arbitrary code 
    on the target host. (CVE-2019-0192)

  - A denial of service (DoS) vulnerability exists in the Apache
    Tika subcomponent of Primavera Unifier due to incorrect parsing
    of a crafted sqlite file. An unauthenticated, remote attacker 
    can exploit this issue by convincing a user to open a
    specially crafted file to cause the application to stop 
    responding. (CVE-2018-17197)

  - A server side request forgery exists in the Apache Solr
    subcomponent of Primavera Unifier. An unauthenticated 
    remote attacker can exploit this issue to make Solr
    perform an HTTP GET request to any reachable URL.
    (CVE-2017-3164)

  - A cross-site scripting (XSS) vulnerability exists due to 
    improper validation of user-supplied input before returning 
    it to users. An unauthenticated, remote attacker can exploit 
    this, by convincing a user to click a specially crafted URL, 
    to execute arbitrary script code in a user's browser session,
    which could lead to unauthorized read, update, insert or 
    delete access to a subset of Primavera Unifier data.
    (CVE-2015-9251)

Note that GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpujul2019-5072835.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle Primavera Unifier version 16.2.15.9 / 17.12.11 / 18.8.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0192");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:oracle:primavera_unifier");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_primavera_unifier.nbin");
  script_require_keys("installed_sw/Oracle Primavera Unifier", "www/weblogic");
  script_require_ports("Services/www", 8002);

  exit(0);
}

include('http.inc');
include('vcf.inc');

get_install_count(app_name:'Oracle Primavera Unifier', exit_if_zero:TRUE);

port = get_http_port(default:8002);
get_kb_item_or_exit('www/weblogic/' + port + '/installed');

app_info = vcf::get_app_info(app:'Oracle Primavera Unifier', port:port);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'min_version' : '15.1.0.0', 'fixed_version' : '16.2.15.9' },
  { 'min_version' : '17.7.0.0', 'fixed_version' : '17.12.11' },
  { 'min_version' : '18.8.0.0', 'fixed_version' : '18.8.11' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE); 
