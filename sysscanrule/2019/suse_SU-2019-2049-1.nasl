#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:2049-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(127765);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2018-16889", "CVE-2019-3821");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : ceph (SUSE-SU-2019:2049-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ceph fixes the following issues :

Security issues fixed :

CVE-2019-3821: civetweb: fix file descriptor leak (bsc#1125080)

CVE-2018-16889: rgw: sanitize customer encryption keys from log output
in v4 auth (bsc#1121567)

Non-security issues fixed: install grafana dashboards world readable
(bsc#1136110)

upgrade results in cluster outage (bsc#1132396)

ceph status reports 'HEALTH_WARN 3 monitors have not enabled msgr2'
(bsc#1124957)

Dashboard: Opening tcmu-runner perf counters results in a 404
(bsc#1135388)

RadosGW stopped expiring objects (bsc#1133139)

Ceph does not recover when rebuilding every OSD (bsc#1133461)

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1121567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1123360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1124957"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1125080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1125899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1131984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1132396"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1133139"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1133461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1135030"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1135219"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1135221"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1135388"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1136110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16889/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-3821/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20192049-1/
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

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2019-2049=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2019-2049=1

SUSE Enterprise Storage 6:zypper in -t patch
SUSE-Storage-6-2019-2049=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-fuse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-mds-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-mgr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-mgr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-mon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-osd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-osd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-radosgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-radosgw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ceph-test-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cephfs-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcephfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcephfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcephfs2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librados-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librados-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librados2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libradospp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librbd1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librgw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librgw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:librgw2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-ceph-argparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-cephfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rados-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-rgw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rados-objclass-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rbd-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rbd-fuse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rbd-mirror");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rbd-mirror-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rbd-nbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:rbd-nbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
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
if (os_ver == "SLES15" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"ceph-test-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"ceph-test-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", cpu:"x86_64", reference:"ceph-test-debugsource-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-base-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-base-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-debugsource-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-fuse-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-fuse-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-mds-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-mds-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-mgr-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-mgr-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-mon-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-mon-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-osd-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-osd-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-radosgw-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-radosgw-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"cephfs-shell-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rbd-fuse-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rbd-fuse-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rbd-mirror-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rbd-mirror-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rbd-nbd-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rbd-nbd-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-common-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-common-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"ceph-debugsource-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libcephfs-devel-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libcephfs2-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libcephfs2-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librados-devel-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librados-devel-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librados2-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librados2-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"libradospp-devel-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librbd-devel-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librbd1-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librbd1-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librgw-devel-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librgw2-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"librgw2-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-ceph-argparse-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-cephfs-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-cephfs-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-rados-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-rados-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-rbd-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-rbd-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-rgw-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-rgw-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"rados-objclass-devel-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"ceph-test-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"ceph-test-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", cpu:"x86_64", reference:"ceph-test-debugsource-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-base-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-base-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-debugsource-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-fuse-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-fuse-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-mds-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-mds-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-mgr-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-mgr-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-mon-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-mon-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-osd-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-osd-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-radosgw-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-radosgw-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"cephfs-shell-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rbd-fuse-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rbd-fuse-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rbd-mirror-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rbd-mirror-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rbd-nbd-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rbd-nbd-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-common-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-common-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"ceph-debugsource-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libcephfs-devel-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libcephfs2-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libcephfs2-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librados-devel-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librados-devel-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librados2-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librados2-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"libradospp-devel-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librbd-devel-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librbd1-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librbd1-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librgw-devel-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librgw2-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"librgw2-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-ceph-argparse-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-cephfs-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-cephfs-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-rados-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-rados-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-rbd-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-rbd-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-rgw-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"python3-rgw-debuginfo-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"rados-objclass-devel-14.2.1.468+g994fd9e0cc-3.3.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ceph");
}
