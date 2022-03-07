#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127004);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/25  9:40:28");

  script_cve_id(
    "CVE-2019-12749"
  );

  script_name(english:"EulerOS 2.0 SP8 : dbus (EulerOS-SA-2019-1767)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the dbus packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerability :

  - dbus before 1.10.28, 1.12.x before 1.12.16, and 1.13.x
    before 1.13.12, as used in DBusServer in Canonical
    Upstart in Ubuntu 14.04 (and in some, less common, uses
    of dbus-daemon), allows cookie spoofing because of
    symlink mishandling in the reference implementation of
    DBUS_COOKIE_SHA1 in the libdbus library. (This only
    affects the DBUS_COOKIE_SHA1 authentication mechanism.)
    A malicious client with write access to its own home
    directory could manipulate a ~/.dbus-keyrings symlink
    to cause a DBusServer with a different uid to read and
    write in unintended locations. In the worst case, this
    could result in the DBusServer reusing a cookie that is
    known to the malicious client, and treating that cookie
    as evidence that a subsequent client connection came
    from an attacker-chosen uid, allowing authentication
    bypass.(CVE-2019-12749)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1767
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected dbus package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dbus-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dbus-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dbus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dbus-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dbus-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dbus-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

flag = 0;

pkgs = ["dbus-1.12.10-1.h4.eulerosv2r8",
        "dbus-common-1.12.10-1.h4.eulerosv2r8",
        "dbus-daemon-1.12.10-1.h4.eulerosv2r8",
        "dbus-devel-1.12.10-1.h4.eulerosv2r8",
        "dbus-libs-1.12.10-1.h4.eulerosv2r8",
        "dbus-tools-1.12.10-1.h4.eulerosv2r8",
        "dbus-x11-1.12.10-1.h4.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dbus");
}
