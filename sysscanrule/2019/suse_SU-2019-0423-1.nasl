#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:0423-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(122309);
  script_version("1.2");
  script_cvs_date("Date: 2019/03/25 11:32:59");

  script_cve_id("CVE-2018-16872", "CVE-2018-18954", "CVE-2018-19364", "CVE-2018-19489", "CVE-2019-6778");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : qemu (SUSE-SU-2019:0423-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for qemu fixes the following issues :

Security issues fixed :

CVE-2019-6778: Fixed a heap buffer overflow issue in the SLiRP
networking implementation (bsc#1123156).

CVE-2018-16872: Fixed a host security vulnerability related to
handling symlinks in usb-mtp (bsc#1119493).

CVE-2018-19489: Fixed a denial of service vulnerability in virtfs
(bsc#1117275).

CVE-2018-19364: Fixed a use-after-free if the virtfs interface
resulting in a denial of service (bsc#1116717).

CVE-2018-18954: Fixed a denial of service vulnerability related to
PowerPC PowerNV memory operations (bsc#1114957).

Non-security issues fixed: Improved disk performance for qemu on xen
(bsc#1100408).

Fixed xen offline migration (bsc#1079730, bsc#1101982, bsc#1063993).

Fixed pwrite64/pread64/write to return 0 over -1 for a zero length
NULL buffer in qemu (bsc#1121600).

Use /bin/bash to echo value into sys fs for ksm control (bsc#1112646).

Return specification exception for unimplemented diag 308 subcodes
rather than a hardware error (bsc#1123179).

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1063993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1079730"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1100408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1101982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1112646"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1114957"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1116717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1117275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1119493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1121600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1123156"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1123179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16872/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-18954/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19364/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-19489/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-6778/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20190423-1/
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

SUSE Linux Enterprise Module for Server Applications 15:zypper in -t
patch SUSE-SLE-Module-Server-Applications-15-2019-423=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-423=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-423=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-dmg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-dmg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-iscsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-block-ssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-guest-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-linux-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-linux-user-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-linux-user-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-s390-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:qemu-x86-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/19");
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
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"qemu-x86-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"qemu-x86-debuginfo-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"qemu-s390-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"s390x", reference:"qemu-s390-debuginfo-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"qemu-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"qemu-block-curl-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"qemu-block-curl-debuginfo-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"qemu-block-iscsi-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"qemu-block-iscsi-debuginfo-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"qemu-block-rbd-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"qemu-block-rbd-debuginfo-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"qemu-block-ssh-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"qemu-block-ssh-debuginfo-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"qemu-debuginfo-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"qemu-debugsource-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"qemu-guest-agent-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"qemu-guest-agent-debuginfo-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"qemu-lang-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"qemu-kvm-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"qemu-block-dmg-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"qemu-block-dmg-debuginfo-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"qemu-debuginfo-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"qemu-debugsource-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"qemu-extra-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"qemu-extra-debuginfo-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"qemu-linux-user-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"qemu-linux-user-debuginfo-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"qemu-linux-user-debugsource-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"qemu-debuginfo-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"qemu-debugsource-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"qemu-tools-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"qemu-tools-debuginfo-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"qemu-block-dmg-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"qemu-block-dmg-debuginfo-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"qemu-debuginfo-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"qemu-debugsource-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"qemu-extra-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"qemu-extra-debuginfo-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"qemu-linux-user-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"qemu-linux-user-debuginfo-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"qemu-linux-user-debugsource-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"qemu-debuginfo-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"qemu-debugsource-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"qemu-tools-2.11.2-9.20.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"qemu-tools-debuginfo-2.11.2-9.20.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu");
}
