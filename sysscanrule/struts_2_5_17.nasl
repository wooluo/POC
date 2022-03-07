include("compat.inc");

if (description)
{
  script_id(112036);
  script_version("1.2");
  script_cvs_date("Date: 2018/08/24 20:37:41");

  script_cve_id("CVE-2018-11776");
  script_bugtraq_id(105125);
  script_xref(name:"IAVA", value:"2018-A-0275");

  script_name(english:"Apache Struts CVE-2018-11776 Results With No Namespace Possible Remote Code Execution (S2-057)");
  script_summary(english:"Checks the Struts 2 version.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host uses a Java framework
that is affected by a possible remote code execution.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Struts running on the remote host is 2.3.x
prior to 2.3.35, or 2.5.x prior to 2.5.17. It, therefore, contains a
possible remote code execution vulnerability when results are used
without setting a namespace along with an upper action that does not
have a namespace set or has a wildcard namespace set.

Note that we did not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/S2-057");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2018/Aug/46");
  script_set_attribute(attribute:"see_also", value:"https://semmle.com/news/apache-struts-CVE-2018-11776");
  script_set_attribute(attribute:"see_also", value:"https://lgtm.com/blog/apache_struts_CVE-2018-11776");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.3.35 or 2.5.17 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"remote code execution");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"Copyright (C) 2004-2018 WebRAY");

  script_dependencies("os_fingerprint.nasl", "struts_detect_win.nbin", "struts_detect_nix.nbin");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("installed_sw/Apache Struts","installed_sw/Struts");

  exit(0);
}

include("vcf.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

win_local = FALSE;
os = get_kb_item_or_exit("Host/OS");
if ('windows' >< tolower(os)) win_local = TRUE;

app_info = vcf::get_app_info(app:"Apache Struts", win_local:win_local);

vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { "min_version" : "2.3", "max_version" : "2.3.34", "fixed_version" : "2.3.35" },
  { "min_version" : "2.5", "max_version" : "2.5.16", "fixed_version" : "2.5.17" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
