#
# (C) WebRAY Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0061. The text
# itself is copyright (C) ZTE, Inc.

include("compat.inc");

if (description)
{
  script_id(127254);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:04:15");

  script_cve_id("CVE-2019-3816");
  script_bugtraq_id(107368);

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : openwsman Vulnerability (NS-SA-2019-0061)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has openwsman packages installed that are affected
by a vulnerability:

  - Openwsman, versions up to and including 2.6.9, are
    vulnerable to arbitrary file disclosure because the
    working directory of openwsmand daemon was set to root
    directory. A remote, unauthenticated attacker can
    exploit this vulnerability by sending a specially
    crafted HTTP request to openwsman server.
    (CVE-2019-3816)

Note that GizaNE has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0061");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL openwsman packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3816");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "libwsman-devel-2.6.3-6.git4391e5c.el7_6",
    "libwsman1-2.6.3-6.git4391e5c.el7_6",
    "openwsman-client-2.6.3-6.git4391e5c.el7_6",
    "openwsman-debuginfo-2.6.3-6.git4391e5c.el7_6",
    "openwsman-perl-2.6.3-6.git4391e5c.el7_6",
    "openwsman-python-2.6.3-6.git4391e5c.el7_6",
    "openwsman-ruby-2.6.3-6.git4391e5c.el7_6",
    "openwsman-server-2.6.3-6.git4391e5c.el7_6"
  ],
  "CGSL MAIN 5.04": [
    "libwsman-devel-2.6.3-6.git4391e5c.el7_6",
    "libwsman1-2.6.3-6.git4391e5c.el7_6",
    "openwsman-client-2.6.3-6.git4391e5c.el7_6",
    "openwsman-debuginfo-2.6.3-6.git4391e5c.el7_6",
    "openwsman-perl-2.6.3-6.git4391e5c.el7_6",
    "openwsman-python-2.6.3-6.git4391e5c.el7_6",
    "openwsman-ruby-2.6.3-6.git4391e5c.el7_6",
    "openwsman-server-2.6.3-6.git4391e5c.el7_6"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openwsman");
}
