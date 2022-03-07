#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2185-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(128048);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/21  9:43:47");

  script_cve_id("CVE-2019-11460", "CVE-2019-11461", "CVE-2019-8308");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : flatpak (SUSE-SU-2019:2185-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for flatpak fixes the following issues :

Security issues fixed :

CVE-2019-8308: Fixed a potential sandbox escape via /proc
(bsc#1125431).

CVE-2019-11460: Fixed a compromised thumbnailer may escape the
bubblewrap sandbox used to confine thumbnailers by using the TIOCSTI
ioctl (bsc#1133043).

CVE-2019-11461: Fixed a compromised thumbnailer may escape the
bubblewrap sandbox used to confine thumbnailers by using the TIOCSTI
ioctl (bsc#1133041).

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1125431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1133041"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1133043"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11460/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-11461/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-8308/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192185-1/
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Desktop Applications 15:zypper in -t
patch SUSE-SLE-Module-Desktop-Applications-15-2019-2185=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flatpak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flatpak-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flatpak-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:flatpak-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libflatpak0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libflatpak0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-Flatpak");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", reference:"flatpak-0.10.4-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"flatpak-debuginfo-0.10.4-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"flatpak-debugsource-0.10.4-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"flatpak-devel-0.10.4-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libflatpak0-0.10.4-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libflatpak0-debuginfo-0.10.4-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"typelib-1_0-Flatpak-1_0-0.10.4-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"flatpak-0.10.4-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"flatpak-debuginfo-0.10.4-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"flatpak-debugsource-0.10.4-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"flatpak-devel-0.10.4-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libflatpak0-0.10.4-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libflatpak0-debuginfo-0.10.4-4.10.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"typelib-1_0-Flatpak-1_0-0.10.4-4.10.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "flatpak");
}