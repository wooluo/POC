#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-f9f78895c3.
#

include("compat.inc");

if (description)
{
  script_id(127944);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/20 11:58:10");

  script_cve_id("CVE-2019-14744");
  script_xref(name:"FEDORA", value:"2019-f9f78895c3");

  script_name(english:"Fedora 30 : kdelibs3 (2019-f9f78895c3)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes **CVE-2019-14744 (kconfig arbitrary shell code
execution)** in the KDE 3 compatibility version of kdelibs used by
legacy KDE 3 applications.

The full list of fixes in this `kdelibs3` build :

  - fixes **CVE-2019-14744** - `kconfig`: malicious
    `.desktop` files (and others) would execute code.
    KConfig had a well-meaning feature that allowed
    configuration files to execute arbitrary shell commands.
    Unfortunately, this could be abused by untrusted
    `.desktop` files to execute arbitrary code as the target
    user, without the user even running the `.desktop` file.
    Therefore, this update removes that ill-fated feature.
    (Backported by Kevin Kofler from upstream: `kf5-kconfig`
    fix by David Faure, `kdelibs` 4 backport by Kai Uwe
    Broulik.)

  - adds native support for **xdg-user-dirs** for *Desktop*
    and *Documents*, without shelling out to `xdg-user-dir`
    from the config file. This is needed due to the above
    security fix. (This feature was previously implemented
    in the Fedora `kde-settings` by shelling out to
    `xdg-user-dir` from the config file using the KConfig
    feature removed above.) (Backported by Kevin Kofler from
    Trinity Desktop / Timothy Pearson.)

  - fixes a **KJS double-free** that could crash legacy KDE
    3 applications such as Quanta Plus when trying to
    execute JavaScript. (Backported by OpenSUSE / Wolfgang
    Bauer from Trinity Desktop / Timothy Pearson.)

Note that WebRAY Network Security has extracted the preceding
description block directly from the Fedora update system website.
WebRAY has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-f9f78895c3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdelibs3 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdelibs3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:30");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^30([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 30", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC30", reference:"kdelibs3-3.5.10-101.fc30")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdelibs3");
}
