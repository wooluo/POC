#
# (C) WebRAY Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0079. The text
# itself is copyright (C) ZTE, Inc.

include("compat.inc");

if (description)
{
  script_id(127289);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:04:15");

  script_cve_id("CVE-2019-11234", "CVE-2019-11235");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : freeradius Multiple Vulnerabilities (NS-SA-2019-0079)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has freeradius packages installed that are
affected by multiple vulnerabilities:

  - FreeRADIUS before 3.0.19 mishandles the each
    participant verifies that the received scalar is within
    a range, and that the received group element is a valid
    point on the curve being used protection mechanism, aka
    a Dragonblood issue, a similar issue to CVE-2019-9498
    and CVE-2019-9499. (CVE-2019-11235)

  - FreeRADIUS before 3.0.19 does not prevent use of
    reflection for authentication spoofing, aka a
    Dragonblood issue, a similar issue to CVE-2019-9497.
    (CVE-2019-11234)

Note that GizaNE has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0079");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL freeradius packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11235");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/22");
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
    "freeradius-3.0.13-10.el7_6",
    "freeradius-debuginfo-3.0.13-10.el7_6",
    "freeradius-devel-3.0.13-10.el7_6",
    "freeradius-doc-3.0.13-10.el7_6",
    "freeradius-krb5-3.0.13-10.el7_6",
    "freeradius-ldap-3.0.13-10.el7_6",
    "freeradius-mysql-3.0.13-10.el7_6",
    "freeradius-perl-3.0.13-10.el7_6",
    "freeradius-postgresql-3.0.13-10.el7_6",
    "freeradius-python-3.0.13-10.el7_6",
    "freeradius-sqlite-3.0.13-10.el7_6",
    "freeradius-unixODBC-3.0.13-10.el7_6",
    "freeradius-utils-3.0.13-10.el7_6"
  ],
  "CGSL MAIN 5.04": [
    "freeradius-3.0.13-10.el7_6",
    "freeradius-debuginfo-3.0.13-10.el7_6",
    "freeradius-devel-3.0.13-10.el7_6",
    "freeradius-doc-3.0.13-10.el7_6",
    "freeradius-krb5-3.0.13-10.el7_6",
    "freeradius-ldap-3.0.13-10.el7_6",
    "freeradius-mysql-3.0.13-10.el7_6",
    "freeradius-perl-3.0.13-10.el7_6",
    "freeradius-postgresql-3.0.13-10.el7_6",
    "freeradius-python-3.0.13-10.el7_6",
    "freeradius-sqlite-3.0.13-10.el7_6",
    "freeradius-unixODBC-3.0.13-10.el7_6",
    "freeradius-utils-3.0.13-10.el7_6"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "freeradius");
}
