#
# (C) WebRAY Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0066. The text
# itself is copyright (C) ZTE, Inc.

include("compat.inc");

if (description)
{
  script_id(127264);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:04:15");

  script_cve_id("CVE-2019-3804");

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : cockpit Vulnerability (NS-SA-2019-0066)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has cockpit packages installed that are affected
by a vulnerability:

  - It was found that cockpit used glib's base64 decode
    functionality incorrectly resulting in a denial of
    service attack. An unauthenticated attacker could send a
    specially crafted request with an invalid base64-encoded
    cookie which could cause the web service to crash.
    (CVE-2019-3804)

Note that GizaNE has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0066");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL cockpit packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3804");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/26");
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
    "cockpit-176-4.el7.centos",
    "cockpit-bridge-176-4.el7.centos",
    "cockpit-dashboard-176-4.el7.centos",
    "cockpit-debuginfo-176-4.el7.centos",
    "cockpit-doc-176-4.el7.centos",
    "cockpit-docker-176-4.el7.centos",
    "cockpit-kubernetes-176-4.el7.centos",
    "cockpit-machines-176-4.el7.centos",
    "cockpit-machines-ovirt-176-4.el7.centos",
    "cockpit-packagekit-176-4.el7.centos",
    "cockpit-pcp-176-4.el7.centos",
    "cockpit-storaged-176-4.el7.centos",
    "cockpit-system-176-4.el7.centos",
    "cockpit-tests-176-4.el7.centos",
    "cockpit-ws-176-4.el7.centos"
  ],
  "CGSL MAIN 5.04": [
    "cockpit-176-4.el7.centos",
    "cockpit-bridge-176-4.el7.centos",
    "cockpit-dashboard-176-4.el7.centos",
    "cockpit-debuginfo-176-4.el7.centos",
    "cockpit-doc-176-4.el7.centos",
    "cockpit-docker-176-4.el7.centos",
    "cockpit-kubernetes-176-4.el7.centos",
    "cockpit-machines-176-4.el7.centos",
    "cockpit-machines-ovirt-176-4.el7.centos",
    "cockpit-packagekit-176-4.el7.centos",
    "cockpit-pcp-176-4.el7.centos",
    "cockpit-storaged-176-4.el7.centos",
    "cockpit-system-176-4.el7.centos",
    "cockpit-tests-176-4.el7.centos",
    "cockpit-ws-176-4.el7.centos"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cockpit");
}
