#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127005);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/25  9:40:28");

  script_cve_id(
    "CVE-2019-12795"
  );

  script_name(english:"EulerOS 2.0 SP8 : gvfs (EulerOS-SA-2019-1768)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the gvfs packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerability :

  - daemon/gvfsdaemon.c in gvfsd from GNOME gvfs before
    1.38.3, 1.40.x before 1.40.2, and 1.41.x before 1.41.3
    opened a private D-Bus server socket without
    configuring an authorization rule. A local attacker
    could connect to this server socket and issue D-Bus
    method calls. (Note that the server socket only accepts
    a single connection, so the attacker would have to
    discover the server and connect to the socket before
    its owner does.)(CVE-2019-12795)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1768
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected gvfs package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-afc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-afp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-archive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-goa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-gphoto2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-mtp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-smb");
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

pkgs = ["gvfs-1.38.1-1.h1.eulerosv2r8",
        "gvfs-afc-1.38.1-1.h1.eulerosv2r8",
        "gvfs-afp-1.38.1-1.h1.eulerosv2r8",
        "gvfs-archive-1.38.1-1.h1.eulerosv2r8",
        "gvfs-client-1.38.1-1.h1.eulerosv2r8",
        "gvfs-devel-1.38.1-1.h1.eulerosv2r8",
        "gvfs-fuse-1.38.1-1.h1.eulerosv2r8",
        "gvfs-goa-1.38.1-1.h1.eulerosv2r8",
        "gvfs-gphoto2-1.38.1-1.h1.eulerosv2r8",
        "gvfs-mtp-1.38.1-1.h1.eulerosv2r8",
        "gvfs-smb-1.38.1-1.h1.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gvfs");
}
