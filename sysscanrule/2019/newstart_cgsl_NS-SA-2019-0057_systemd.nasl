#
# (C) WebRAY Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0057. The text
# itself is copyright (C) ZTE, Inc.

include("compat.inc");

if (description)
{
  script_id(127248);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:04:15");

  script_cve_id("CVE-2019-3815", "CVE-2019-6454");
  script_bugtraq_id(107081);

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : systemd Multiple Vulnerabilities (NS-SA-2019-0057)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has systemd packages installed that are affected
by multiple vulnerabilities:

  - A memory leak was discovered in the backport of fixes
    for CVE-2018-16864 in Red Hat Enterprise Linux. Function
    dispatch_message_real() in journald-server.c does not
    free the memory allocated by set_iovec_field_free() to
    store the `_CMDLINE=` entry. A local attacker may use
    this flaw to make systemd-journald crash.
    (CVE-2019-3815)

  - It was discovered that systemd allocates a buffer large
    enough to store the path field of a dbus message without
    performing enough checks. A local attacker may trigger
    this flaw by sending a dbus message to systemd with a
    large path making systemd crash or possibly elevating
    his privileges. (CVE-2019-6454)

Note that GizaNE has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0057");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL systemd packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6454");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/28");
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
    "libgudev1-219-62.el7_6.5.cgslv5.0.13.g4dd39ae.lite",
    "libgudev1-devel-219-62.el7_6.5.cgslv5.0.13.g4dd39ae.lite",
    "systemd-219-62.el7_6.5.cgslv5.0.13.g4dd39ae.lite",
    "systemd-debuginfo-219-62.el7_6.5.cgslv5.0.13.g4dd39ae.lite",
    "systemd-devel-219-62.el7_6.5.cgslv5.0.13.g4dd39ae.lite",
    "systemd-journal-gateway-219-62.el7_6.5.cgslv5.0.13.g4dd39ae.lite",
    "systemd-libs-219-62.el7_6.5.cgslv5.0.13.g4dd39ae.lite",
    "systemd-networkd-219-62.el7_6.5.cgslv5.0.13.g4dd39ae.lite",
    "systemd-python-219-62.el7_6.5.cgslv5.0.13.g4dd39ae.lite",
    "systemd-resolved-219-62.el7_6.5.cgslv5.0.13.g4dd39ae.lite",
    "systemd-sysv-219-62.el7_6.5.cgslv5.0.13.g4dd39ae.lite"
  ],
  "CGSL MAIN 5.04": [
    "libgudev1-219-62.el7_6.5.cgslv5.0.9.g8d6a4d9",
    "libgudev1-devel-219-62.el7_6.5.cgslv5.0.9.g8d6a4d9",
    "systemd-219-62.el7_6.5.cgslv5.0.9.g8d6a4d9",
    "systemd-debuginfo-219-62.el7_6.5.cgslv5.0.9.g8d6a4d9",
    "systemd-devel-219-62.el7_6.5.cgslv5.0.9.g8d6a4d9",
    "systemd-journal-gateway-219-62.el7_6.5.cgslv5.0.9.g8d6a4d9",
    "systemd-libs-219-62.el7_6.5.cgslv5.0.9.g8d6a4d9",
    "systemd-networkd-219-62.el7_6.5.cgslv5.0.9.g8d6a4d9",
    "systemd-python-219-62.el7_6.5.cgslv5.0.9.g8d6a4d9",
    "systemd-resolved-219-62.el7_6.5.cgslv5.0.9.g8d6a4d9",
    "systemd-sysv-219-62.el7_6.5.cgslv5.0.9.g8d6a4d9"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "systemd");
}
