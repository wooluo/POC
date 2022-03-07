#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:1574-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(126063);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/27 13:33:26");

  script_cve_id("CVE-2019-12435");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : samba (SUSE-SU-2019:1574-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for samba fixes the following issues :

Security issues fixed :

CVE-2019-12435: zone operations can crash rpc server; (bso#13922);
(bsc#1137815).

Other issues fixed: Fix cephwrap_flistxattr() debug message;
(bso#13940); (bsc#1134697).

Add ceph_snapshots VFS module; (jsc#SES-183).

Fix vfs_ceph realpath; (bso#13918); (bsc#1134452).

MacOS credit accounting breaks with async SESSION SETUP;
(bsc#1125601); (bso#13796).

Mac OS X SMB2 implmenetation sees Input/output error or Resource
temporarily unavailable and drops connection; (bso#13698)

Explicitly enable libcephfs POSIX ACL support; (bso#13896);
(bsc#1130245).

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1125601"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1130245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1134452"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1134697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1137815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-12435/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20191574-1/
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

SUSE Linux Enterprise Module for Python2 15-SP1:zypper in -t patch
SUSE-SLE-Module-Python2-15-SP1-2019-1574=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2019-1574=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2019-1574=1

SUSE Linux Enterprise High Availability 15-SP1:zypper in -t patch
SUSE-SLE-Product-HA-15-SP1-2019-1574=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ctdb-pcp-pmda");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ctdb-pcp-pmda-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ctdb-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ctdb-tests-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-samr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-samr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-samr0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-samr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy-python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy-python3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy0-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy0-python3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy0-python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-ad-dc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-ad-dc-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-ad-dc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-ceph-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-dsdb-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-dsdb-modules-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-python-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-python3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/20");
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
if (os_ver == "SLES15" && (! ereg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0/1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! ereg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"samba-ceph-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"samba-ceph-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libdcerpc-samr0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libdcerpc-samr0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libsamba-policy0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libsamba-policy0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libsamba-policy0-python3-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libsamba-policy0-python3-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libsmbclient0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libsmbclient0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"samba-ad-dc-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"samba-ad-dc-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"samba-client-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"samba-client-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"samba-libs-python-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"samba-libs-python-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"samba-libs-python3-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"samba-libs-python3-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libdcerpc0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libdcerpc0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libndr-nbt0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libndr-nbt0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libndr-standard0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libndr-standard0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libndr0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libndr0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libnetapi0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libnetapi0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libsamba-credentials0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libsamba-credentials0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libsamba-errors0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libsamba-errors0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libsamba-passdb0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libsamba-passdb0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libsamba-util0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libsamba-util0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libsamdb0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libsamdb0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libsmbconf0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libsmbconf0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libsmbldap2-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libsmbldap2-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libtevent-util0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libtevent-util0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libwbclient0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"libwbclient0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"samba-libs-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"samba-libs-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"samba-winbind-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"samba-winbind-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ctdb-pcp-pmda-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ctdb-pcp-pmda-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ctdb-tests-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ctdb-tests-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsamba-policy-python-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"samba-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"samba-debugsource-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"samba-test-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"samba-test-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libdcerpc-binding0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libdcerpc-binding0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libdcerpc-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libdcerpc-samr-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libdcerpc-samr0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libdcerpc-samr0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libdcerpc0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libdcerpc0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libndr-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libndr-krb5pac-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libndr-krb5pac0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libndr-krb5pac0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libndr-nbt-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libndr-nbt0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libndr-nbt0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libndr-standard-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libndr-standard0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libndr-standard0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libndr0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libndr0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libnetapi-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libnetapi0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libnetapi0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsamba-credentials-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsamba-credentials0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsamba-credentials0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsamba-errors-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsamba-errors0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsamba-errors0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsamba-hostconfig-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsamba-hostconfig0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsamba-hostconfig0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsamba-passdb-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsamba-passdb0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsamba-passdb0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsamba-policy-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsamba-policy-python3-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsamba-policy0-python3-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsamba-policy0-python3-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsamba-util-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsamba-util0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsamba-util0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsamdb-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsamdb0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsamdb0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsmbclient-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsmbclient0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsmbclient0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsmbconf-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsmbconf0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsmbconf0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsmbldap-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsmbldap2-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libsmbldap2-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libtevent-util-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libtevent-util0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libtevent-util0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libwbclient-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libwbclient0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libwbclient0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"samba-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"samba-client-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"samba-client-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"samba-core-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"samba-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"samba-debugsource-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"samba-libs-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"samba-libs-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"samba-libs-python3-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"samba-libs-python3-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"samba-python3-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"samba-python3-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"samba-winbind-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"samba-winbind-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-policy0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-policy0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-ad-dc-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-ad-dc-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-debugsource-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-dsdb-modules-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-dsdb-modules-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-libs-python-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-libs-python-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-python-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-python-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"samba-ceph-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"samba-ceph-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libdcerpc-samr0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libdcerpc-samr0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libsamba-policy0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libsamba-policy0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libsamba-policy0-python3-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libsamba-policy0-python3-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libsmbclient0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libsmbclient0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"samba-ad-dc-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"samba-ad-dc-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"samba-client-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"samba-client-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"samba-libs-python-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"samba-libs-python-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"samba-libs-python3-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"samba-libs-python3-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libdcerpc0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libdcerpc0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libndr-nbt0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libndr-nbt0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libndr-standard0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libndr-standard0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libndr0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libndr0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libnetapi0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libnetapi0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libsamba-credentials0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libsamba-credentials0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libsamba-errors0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libsamba-errors0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libsamba-passdb0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libsamba-passdb0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libsamba-util0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libsamba-util0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libsamdb0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libsamdb0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libsmbconf0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libsmbconf0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libsmbldap2-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libsmbldap2-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libtevent-util0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libtevent-util0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libwbclient0-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"libwbclient0-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"samba-libs-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"samba-libs-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"samba-winbind-32bit-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"samba-winbind-32bit-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ctdb-pcp-pmda-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ctdb-pcp-pmda-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ctdb-tests-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ctdb-tests-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsamba-policy-python-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"samba-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"samba-debugsource-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"samba-test-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"samba-test-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libdcerpc-binding0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libdcerpc-binding0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libdcerpc-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libdcerpc-samr-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libdcerpc-samr0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libdcerpc-samr0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libdcerpc0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libdcerpc0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libndr-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libndr-krb5pac-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libndr-krb5pac0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libndr-krb5pac0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libndr-nbt-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libndr-nbt0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libndr-nbt0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libndr-standard-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libndr-standard0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libndr-standard0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libndr0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libndr0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libnetapi-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libnetapi0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libnetapi0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsamba-credentials-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsamba-credentials0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsamba-credentials0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsamba-errors-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsamba-errors0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsamba-errors0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsamba-hostconfig-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsamba-hostconfig0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsamba-hostconfig0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsamba-passdb-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsamba-passdb0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsamba-passdb0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsamba-policy-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsamba-policy-python3-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsamba-policy0-python3-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsamba-policy0-python3-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsamba-util-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsamba-util0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsamba-util0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsamdb-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsamdb0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsamdb0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsmbclient-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsmbclient0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsmbclient0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsmbconf-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsmbconf0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsmbconf0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsmbldap-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsmbldap2-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libsmbldap2-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libtevent-util-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libtevent-util0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libtevent-util0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libwbclient-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libwbclient0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libwbclient0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"samba-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"samba-client-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"samba-client-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"samba-core-devel-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"samba-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"samba-debugsource-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"samba-libs-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"samba-libs-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"samba-libs-python3-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"samba-libs-python3-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"samba-python3-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"samba-python3-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"samba-winbind-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"samba-winbind-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-policy0-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-policy0-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-ad-dc-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-ad-dc-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-debugsource-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-dsdb-modules-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-dsdb-modules-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-libs-python-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-libs-python-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-python-4.9.5+git.176.375e1f05788-3.6.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-python-debuginfo-4.9.5+git.176.375e1f05788-3.6.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
