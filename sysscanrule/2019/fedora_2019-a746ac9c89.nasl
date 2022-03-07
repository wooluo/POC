#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-a746ac9c89.
#

include("compat.inc");

if (description)
{
  script_id(127873);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/20 11:58:13");

  script_cve_id("CVE-2019-14744");
  script_xref(name:"FEDORA", value:"2019-a746ac9c89");

  script_name(english:"Fedora 30 : 6:kdelibs / kde-settings (2019-a746ac9c89)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes **CVE-2019-14744 (kconfig arbitrary shell code
execution)** in the compatibility library `kdelibs` 4 used by legacy
applications (not yet ported to KDE Frameworks 5). The included
`kde-settings` update removes obsolete settings that conflict with the
security fix and are no longer needed (see below for details).

The full list of fixes in the `kdelibs` 4 build :

  - fixes **CVE-2019-14744 (#1740138, #1740140)** &ndash;
    `kconfig`: malicious `.desktop` files (and others) would
    execute code. KConfig had a well-meaning feature that
    allowed configuration files to execute arbitrary shell
    commands. Unfortunately, this could be abused by
    untrusted `.desktop` files to execute arbitrary code as
    the target user, without the user even running the
    `.desktop` file. Therefore, this update removes that
    ill-fated feature. (Patch from upstream: `kf5-kconfig`
    fix by David Faure, `kdelibs` 4 backport by Kai Uwe
    Broulik.)

  - fixes **#917848** &ndash; removes support for the
    `gamin` file watching service which is unmaintained and
    buggy and can lead to application lockups. KDirWatch now
    relies exclusively on `inotify` (directly). (Packaging
    fix by Rex Dieter.)

  - fixes **#1730770** &ndash; removes an unused dependency
    on the obsolete `xf86misc` library. (Packaging fix by
    Kevin Kofler.)

The fixes in the `kde-settings` build remove settings that were
calling `xdg-user-dir`, because the above CVE-2019-14744 fix drops
support for running shell commands from configuration files from
KConfig and because the settings are all no longer needed (because
they either only reproduce default behavior or were commented out) :

  -
    `/usr/share/kde-settings/kde-profile/default/share/confi
    g/kdeglobals`,
    `/usr/share/kde-settings/kde-profile/minimal/share/confi
    g/kdeglobals`: Remove the `[Paths]` section. The
    `Desktop` and `Documents` directories that were set
    there are already detected by default by `kdelibs` 4 (it
    has native support for xdg-user-dirs and does not need
    the external `xdg-user-dir` command invocation), and now
    also by `kdelibs3 >= 3.5.10-101` (which has native
    xdg-user-dirs support backported). The `Trash` setting
    was already commented out.

  -
    `/usr/share/kde-settings/kde-profile/default/xdg/baloofi
    lerc`: Delete the commented-out `folders` setting that
    attempts to call `xdg-user-dir`.

Note that WebRAY Network Security has extracted the preceding
description block directly from the Fedora update system website.
WebRAY has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-a746ac9c89"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 6:kdelibs and / or kde-settings packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:6:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kde-settings");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:30");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/14");
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
if (rpm_check(release:"FC30", reference:"kdelibs-4.14.38-15.fc30", epoch:"6")) flag++;
if (rpm_check(release:"FC30", reference:"kde-settings-30.3-1.fc30")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "6:kdelibs / kde-settings");
}
