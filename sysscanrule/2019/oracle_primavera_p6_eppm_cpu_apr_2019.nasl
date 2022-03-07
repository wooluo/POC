#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124169);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/30 14:30:16");

  script_cve_id(
    "CVE-2016-1000031",
    "CVE-2017-9798",
    "CVE-2018-0734",
    "CVE-2018-0735",
    "CVE-2018-5407",
    "CVE-2018-8034",
    "CVE-2018-11763",
    "CVE-2018-11784",
    "CVE-2018-19360",
    "CVE-2018-19361",
    "CVE-2018-19362",
    "CVE-2019-2701"
  );
  script_bugtraq_id(
    93604,
    100872,
    104895,
    105414,
    105524,
    105750,
    105758,
    105897
  );
  script_xref(name:"IAVA", value:"2019-A-0126");

  script_name(english:"Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM) Multiple Vulnerabilities (Apr 2019 CPU)");
  script_summary(english:"Checks the version of Oracle Primavera P6 EPPM.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Oracle Primavera
P6 Enterprise Project Portfolio Management (EPPM) installation running
on the remote web server is 8.4 prior to 8.4.15.10, 15.x prior to
15.2.18.4, 16.x prior to 16.2.17.2, 17.x prior to 17.12.12.0, or 18.x
prior to 18.8.8.0. It is, therefore, affected by multiple
vulnerabilities:

  - A deserialization vulnerability in Apache Commons
    FileUpload allows for remote code execution.
    (CVE-2016-1000031)

  - A denial of service vulnerability in the bundled
    third-party component OpenSSL library's DSA signature
    algorithm that renders it vulnerable to a timing side
    channel attack. An attacker could leverage this
    vulnerability to recover the private key.
    (CVE-2018-0734)

  - A deserialization vulnerability in jackson-databind, a
    fast and powerful JSON library for Java, allows an
    unauthenticated user to perform code execution. The
    issue was resolved by extending the blacklist and
    blocking more classes from polymorphic deserialization.
    (CVE-2018-19362)

Note that GizaNE has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle Primavera P6 Enterprise Project Portfolio Management
(EPPM) version 8.4.15.10 / 15.2.18.4 / 16.2.17.2 / 17.12.12.0 / 18.8.8.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1000031");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:oracle:primavera_p6_eppm");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { "min_version" : "8.4.0.0", "fixed_version" : "8.4.15.10" },
  { "min_version" : "15.1.0.0", "fixed_version" : "15.2.18.4" },
  { "min_version" : "16.2.0.0", "fixed_version" : "16.2.17.2" },
  { "min_version" : "17.7.0.0", "fixed_version" : "17.12.12.0" },
  { "min_version" : "18.0.0.0", "fixed_version" : "18.8.8.0" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
