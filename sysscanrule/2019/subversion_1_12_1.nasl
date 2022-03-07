#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127137);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 15:23:38");

  script_cve_id("CVE-2018-11782", "CVE-2019-0203");
  script_xref(name:"IAVA", value:"2019-A-0279");

  script_name(english:"Apache Subversion < 1.9.11 / 1.10.x < 1.10.5 / 1.11.x / 1.12.x < 1.12.1 Multiple Vulnerabilities");
  script_summary(english:"Checks Subversion Server version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Subversion Server is prior to 1.9.11, 1.10.x prior to 1.10.5, 1.11.x or 1.12.x prior to 1.12.1 
and is, therefore, affected by multiple vulnerabilities:

 - A denial of service (DoS) vulnerability exists in Subversion's svnserve server process due to that the process may exit
   when a well-formed read-only request produces a particular answer. A remote authenticated attacker can exploit this issue
   to cause a denial of service attack. (CVE-2018-11782)

 - A denial of service (DoS) vulnerability exists in Subversion's svnserve server process due to that the process may exit
   when a client sends certain sequences of protocol commands. A remote unauthenticated attacker can exploit this issue,
   If the server is configured with anonymous access enabled, to cause a remote denial of service attack. (CVE-2019-0203)

");
  script_set_attribute(attribute:"see_also", value:"https://subversion.apache.org/security/CVE-2019-0203-advisory.txt");
  script_set_attribute(attribute:"see_also", value:"https://subversion.apache.org/security/CVE-2018-11782-advisory.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Subversion Server 1.9.11, 1.10.5, 1.12.1 or later, or apply the vendor-supplied patch or workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0203");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:subversion");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Windows");

  script_dependencies("subversion_installed.nasl");
  script_require_keys("installed_sw/Subversion Server");

  exit(0);
}

include("vcf.inc");
include("vcf_extras.inc");

app_info = vcf::get_app_info(app:"Subversion Server");

constraints = [
  { "fixed_version" : "1.9.11" },
  { "min_version" : "1.10.0", "fixed_version" : "1.10.5" },
  { "min_version" : "1.11.0", "fixed_version" : "1.12.1" }
];

vcf::apache_subversion::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
