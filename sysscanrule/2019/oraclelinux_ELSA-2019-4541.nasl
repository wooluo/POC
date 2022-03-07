#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2019-4541.
#

include("compat.inc");

if (description)
{
  script_id(122141);
  script_version("1.8");
  script_cvs_date("Date: 2019/07/24  9:40:20");

  script_cve_id("CVE-2018-13053", "CVE-2018-16882", "CVE-2018-17972", "CVE-2018-18397", "CVE-2019-5489");

  script_name(english:"Oracle Linux 7 : Unbreakable Enterprise kernel (ELSA-2019-4541)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

[4.14.35-1844.2.5.el7uek]
- x86/apic: Switch all APICs to Fixed delivery mode (Thomas Gleixner) 
[Orabug: 29262403]

[4.14.35-1844.2.4.el7uek]
- x86/platform/UV: Add check of TSC state set by UV BIOS 
(<A HREF='https://oss.oracle.com/mailman/listinfo/el-errata'>mike.travis at hpe.com</A>) [Orabug: 29205471] - x86/tsc: Provide a means to 
disable TSC ART (<A HREF='https://oss.oracle.com/mailman/listinfo/el-errata'>mike.travis at hpe.com</A>) [Orabug: 29205471] - x86/tsc: 
Drastically reduce the number of firmware bug warnings 
(<A HREF='https://oss.oracle.com/mailman/listinfo/el-errata'>mike.travis at hpe.com</A>) [Orabug: 29205471] - x86/tsc: Skip TSC test and 
error messages if already unstable (<A HREF='https://oss.oracle.com/mailman/listinfo/el-errata'>mike.travis at hpe.com</A>) [Orabug: 
29205471] - x86/tsc: Add option that TSC on Socket 0 being non-zero is 
valid (<A HREF='https://oss.oracle.com/mailman/listinfo/el-errata'>mike.travis at hpe.com</A>) [Orabug: 29205471] - scsi: lpfc: Enable 
Management features for IF_TYPE=6 (James Smart) [Orabug: 29248376]

[4.14.35-1844.2.3.el7uek]
- RDS: Heap OOB write in rds_message_alloc_sgs() (Mohamed Ghannam) 
[Orabug: 28983233] - proc: restrict kernel stack dumps to root (Jann 
Horn) [Orabug: 29114876] {CVE-2018-17972}
- rds: congestion updates can be missed when kernel low on memory 
(Mukesh Kacker) [Orabug: 29200902] - x86/retpoline: Make 
CONFIG_RETPOLINE depend on compiler support (Zhenzhong Duan) [Orabug: 
29211613] - xen-netback: wake up xenvif_dealloc_kthread when it should 
stop (Dongli Zhang) [Orabug: 29237355] - xen/blkback: rework 
validate_io_op() (Dongli Zhang) [Orabug: 29237430] - xen/blkback: 
optimize validate_io_op() to filter BLKIF_OP_RESERVED_1 operation 
(Dongli Zhang) [Orabug: 29237430] - xen/blkback: do not BUG() for 
invalid blkif_request from frontend (Dongli Zhang) [Orabug: 29237430] - 
net/rds: WARNING: at net/rds/recv.c:222 rds_recv_hs_exthdrs+0xf8/0x1e0 
(Venkat Venkatsubra) [Orabug: 29248238] - kvm: x86: Add AMD's EX_CFG to 
the list of ignored MSRs (Eduardo Habkost) [Orabug: 29254549] - 
alarmtimer: Prevent overflow for relative nanosleep (Thomas Gleixner) 
[Orabug: 29269148] {CVE-2018-13053}

[4.14.35-1844.2.2.el7uek]
- genirq/affinity: Don't return with empty affinity masks on error 
(Thomas Gleixner) [Orabug: 29209330] - x86/apic/x2apic: set affinity of 
a single interrupt to one cpu (Jianchao Wang) [Orabug: 29201434] - 
uek-rpm: Update x86_64 config options (Victor Erminpour) [Orabug: 
29129556] - net: rds: fix excess initialization of the recv SGEs (Zhu 
Yanjun) [Orabug: 29004501] - nvme-pci: fix memory leak on probe failure 
(Keith Busch) [Orabug: 29214245] - nvme-pci: limit max IO size and 
segments to avoid high order allocations (Jens Axboe) [Orabug: 29214245] 
- arm64, dtrace: add non-virtual clocksources to fbt blacklist (Nick 
Alcock) [Orabug: 29220926] - net/rds: ib: Fix endless RNR Retries caused 
by memory allocation failures (Venkat Venkatsubra) [Orabug: 29222874] - 
x86/speculation: simplify IBRS firmware control (Alexandre Chartre) 
[Orabug: 29225114] - x86/speculation: use jump label instead of 
alternative to control IBRS firmware (Alexandre Chartre) [Orabug: 
29225114] - x86/speculation: fix and simplify IBPB control (Alexandre 
Chartre) [Orabug: 29225114] - x86/speculation: use jump label instead of 
alternative to control IBPB (Alexandre Chartre) [Orabug: 29225114] - 
x86/speculation: move ANNOTATE_* macros to a new header file (Alexandre 
Chartre) [Orabug: 29225114] - be2net: Update the driver version to 
12.0.0.0 (Suresh Reddy) [Orabug: 29228473] - be2net: Handle transmit 
completion errors in Lancer (Suresh Reddy) [Orabug: 29228473] - be2net: 
Fix HW stall issue in Lancer (Suresh Reddy) [Orabug: 29228473] - 
x86/platform/UV: Fix GAM MMR references in the UV x2apic code (Mike 
Travis) [Orabug: 29205471] - x86/platform/UV: Fix GAM MMR changes in 
UV4A (Mike Travis) [Orabug: 29205471] - x86/platform/UV: Add references 
to access fixed UV4A HUB MMRs (Mike Travis) [Orabug: 29205471] - 
x86/platform/UV: Fix UV4A support on new Intel Processors (Mike Travis) 
[Orabug: 29205471] - x86/platform/UV: Update uv_mmrs.h to prepare for 
UV4A fixes (Mike Travis) [Orabug: 29205471]

[4.14.35-1844.2.1.el7uek]
- rds: Incorrect rds-info send and retransmission message output 
(Ka-Cheong Poon) [Orabug: 29024033] - mlx4_core: Disable P_Key Violation 
Traps (H&aring kon Bugge) [Orabug: 28861014] - rds: ib: Use a delay when 
reconnecting to the very same IP address (H&aring kon Bugge) [Orabug: 
29161391] - KVM: Fix UAF in nested posted interrupt processing (Cfir 
Cohen) [Orabug: 29172125] {CVE-2018-16882}
- x86/alternative: check int3 breakpoint physical addresses (Alexandre 
Chartre) [Orabug: 29178334] - Change mincore() to count 'mapped' pages 
rather than 'cached' pages (Linus Torvalds) [Orabug: 29187408] 
{CVE-2019-5489}
- net/rds: RDS connection does not reconnect after CQ access violation 
error (Venkat Venkatsubra) [Orabug: 29180514]

[4.14.35-1844.2.0.el7uek]
- userfaultfd: check VM_MAYWRITE was set after verifying the uffd is 
registered (Andrea Arcangeli) [Orabug: 29163742] {CVE-2018-18397}
- userfaultfd: shmem/hugetlbfs: only allow to register VM_MAYWRITE vmas 
(Andrea Arcangeli) [Orabug: 29163742] {CVE-2018-18397}
- ocfs2: don't clear bh uptodate for block read (Junxiao Bi) [Orabug: 
29159655] - ocfs2: clear journal dirty flag after shutdown journal 
(Junxiao Bi) [Orabug: 29154599] - ocfs2: fix panic due to unrecovered 
local alloc (Junxiao Bi) [Orabug: 29154599]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2019-February/008486.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");
include("ksplice.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2018-13053", "CVE-2018-16882", "CVE-2018-17972", "CVE-2018-18397", "CVE-2019-5489");  
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for ELSA-2019-4541");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

kernel_major_minor = get_kb_item("Host/uname/major_minor");
if (empty_or_null(kernel_major_minor)) exit(1, "Unable to determine kernel major-minor level.");
expected_kernel_major_minor = "4.14";
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, "running kernel level " + expected_kernel_major_minor + ", it is running kernel level " + kernel_major_minor);

flag = 0;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-4.14.35-1844.2.5.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-4.14.35-1844.2.5.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-devel-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-devel-4.14.35-1844.2.5.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-devel-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-devel-4.14.35-1844.2.5.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-doc-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-doc-4.14.35-1844.2.5.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-tools-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-tools-4.14.35-1844.2.5.el7uek")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
