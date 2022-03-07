#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(121252);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/18 12:05:36");

  script_cve_id(
    "CVE-2018-0732",
    "CVE-2018-0737",
    "CVE-2019-2512"
  );

  script_name(english:"Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM) Multiple Vulnerabilities (Jan 2019 CPU)");
  script_summary(english:"Checks the version of Oracle Primavera P6 EPPM.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Oracle Primavera
P6 Enterprise Project Portfolio Management (EPPM) installation running
on the remote web server is 8.4 prior to 8.4.15.9, 15.x prior to
15.2.18.3, 16.x prior to 16.2.17.0, 17.x prior to 17.12.10.0, or 18.x
prior to 18.8.5.0. It is, therefore, affected by multiple
vulnerabilities:

  - A denial of service (DoS) vulnerability exists in
    OpenSSL due to an issue processing very large prime
    values during TLS handshakes using a DH(E) based
    ciphersuite. An unauthenticated, remote attacker can
    exploit this issue to cause the client to stop 
    responding. (CVE-2018-0732)

  - The OpenSSL RSA Key generation algorithm is vulnerable
    to a chache timing side channel attack. An attacker can 
    exploit this to potentially recover the private key.
    (CVE-2018-0737)

  - The Web Access subcomponent of Oracle Primavera P6 EPPM
    is affected by a vulnerability which could allow an 
    unauthenticated attacker with HTTP access to compromise
    the system. Successful exploitation of this vulnerability
    require user interaction, and could result in
    unauthorized read/write access to Primavera P6 EPPM data. 
    (CVE-2019-2512)

Note that GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpujan2019-5072801.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle Primavera P6 Enterprise Project Portfolio Management
(EPPM) version 8.4.15.9 / 15.2.18.3 / 16.2.17.0 / 17.12.10.0 / 18.8.5.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0732");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:oracle:primavera_p6_eppm");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_primavera_p6_eppm.nbin");
  script_require_keys("installed_sw/Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM)", "www/weblogic");
  script_require_ports("Services/www", 8004);

  exit(0);
}

include("http.inc");
include("vcf.inc");

get_install_count(app_name:"Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM)", exit_if_zero:TRUE);

port = get_http_port(default:8004);
get_kb_item_or_exit("www/weblogic/" + port + "/installed");

app_info = vcf::get_app_info(app:"Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM)", port:port);

constraints = [
  { "min_version" : "8.4.0.0", "fixed_version" : "8.4.15.9" },
  { "min_version" : "15.0.0.0", "fixed_version" : "15.2.18.3" },
  { "min_version" : "16.0.0.0", "fixed_version" : "16.2.17.0" },
  { "min_version" : "17.0.0.0", "fixed_version" : "17.12.10.0" },
  { "min_version" : "18.0.0.0", "fixed_version" : "18.8.5.0" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
