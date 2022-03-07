#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124020);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/12 11:19:10");

  script_cve_id("CVE-2019-5585");
  script_bugtraq_id(107693);

  script_name(english:"Fortinet FortiClient 6.0.1 < 6.0.5 Local DoS (macOS)");
  script_summary(english:"Checks the version of FortiClient.");

  script_set_attribute(attribute:"synopsis", value:
"The remote MacOS is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Fortinet FortiClient Mac running on the remote host is
prior to 6.0.5. It is, therefore, affected by a Denial of Service (DoS)
vulnerability. An improper access control vulnerability in FortiClientMac
may allow an attacker to affect the application's performance via modifying
the content of a file used by several FortiClientMac processes.");
  # https://fortiguard.com/psirt/FG-IR-19-003
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Fortinet FortiClient 6.0.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5585");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:fortinet:forticlient");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("macos_forticlient_detect.nbin");
  script_require_keys("installed_sw/FortiClient (macOS)", "Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include("vcf.inc");

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/MacOSX/Version')) audit(AUDIT_OS_NOT, 'Mac OS X');

get_kb_item_or_exit('installed_sw/FortiClient (macOS)');
app_info = vcf::get_app_info(app:'FortiClient (macOS)');

constraints = [
  {'min_version' : '6.0.1', 'fixed_version' : '6.0.5'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
