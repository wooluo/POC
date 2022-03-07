#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122718);
  script_version("1.1");
  script_cvs_date("Date: 2019/03/08 13:04:28");

  script_cve_id("CVE-2019-0187");
  script_bugtraq_id(107219);
  script_xref(name:"IAVB", value:"2019-B-0015");

  script_name(english:"Apache JMeter < 5.1 Unauthenticated Remote Code Execution Vulnerability");
  script_summary(english:"Checks the version of Apache JMeter.");

  script_set_attribute(attribute:"synopsis", value:
"A java application on the remote host is affected by
a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"One or more versions of Apache JMeter discovered on the remote
host is affected by an unauthenticated remote code execution 
vulnerability which is possible when JMeter is used in distributed
mode.");

  # https://mail-archives.apache.org/mod_mbox/jmeter-user/201903.mbox/%3CCAH9fUpaUQaFbgY1Zh4OvKSL4wdvGAmVt+n4fegibDoAxK5XARw@mail.gmail.com%3E
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache JMeter 5.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/08");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0187");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:jmeter");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("apache_jmeter_detect_win.nbin");
  script_require_keys("installed_sw/Apache JMeter");

  exit(0);
}

include("vcf.inc");

app = "Apache JMeter";
get_install_count(app_name:app, exit_if_zero:TRUE);

app_info = vcf::get_app_info(app:app);

constraints = [
  { "min_version" : "4.0", "fixed_version" : "5.1" }
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
