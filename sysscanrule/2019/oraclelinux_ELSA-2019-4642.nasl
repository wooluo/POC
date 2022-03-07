#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2019-4642.
#

include("compat.inc");

if (description)
{
  script_id(125235);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/24  9:40:20");

  script_cve_id("CVE-2015-5327", "CVE-2017-18360", "CVE-2018-19985", "CVE-2019-11190");

  script_name(english:"Oracle Linux 6 / 7 : Unbreakable Enterprise kernel (ELSA-2019-4642)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

[4.1.12-124.27.1.el6uek]
- scsi: libfc: sanitize E_D_TOV and R_A_TOV setting (Hannes Reinecke)  [Orabug: 25933179]
- scsi: libfc: use configured rport E_D_TOV (Hannes Reinecke)  [Orabug: 25933179]
- scsi: libfc: additional debugging messages (Hannes Reinecke)  [Orabug: 25933179]
- scsi: libfc: don't advance state machine for incoming FLOGI (Hannes Reinecke)  [Orabug: 25933179]
- scsi: libfc: Do not login if the port is already started (Hannes Reinecke)  [Orabug: 25933179]
- scsi: libfc: Do not drop down to FLOGI for fc_rport_login() (Hannes Reinecke)  [Orabug: 25933179]
- scsi: libfc: Do not take rdata->rp_mutex when processing a -FC_EX_CLOSED ELS response. (Chad Dupuis)  [Orabug: 25933179]
- scsi: libfc: Fixup disc_mutex handling (Hannes Reinecke)  [Orabug: 25933179]
- xve: arm ud tx cq to generate completion interrupts (Ajaykumar Hotchandani)  [Orabug: 28267050]
- net: sched: run ingress qdisc without locks (Alexei Starovoitov)  [Orabug: 29395374]
- bnxt_en: Fix typo in firmware message timeout logic. (Michael Chan)  [Orabug: 29412112]
- bnxt_en: Wait longer for the firmware message response to complete. (Michael Chan)  [Orabug: 29412112]
- mm,vmscan: Make unregister_shrinker() no-op if register_shrinker() failed. (Tetsuo Handa)  [Orabug: 29456281]
- X.509: Handle midnight alternative notation in GeneralizedTime (David Howells)  [Orabug: 29460344]  {CVE-2015-5327}
- X.509: Support leap seconds (David Howells)  [Orabug: 29460344]  {CVE-2015-5327}
- X.509: Fix the time validation [ver #2] (David Howells)  [Orabug: 29460344]  {CVE-2015-5327} {CVE-2015-5327}
- be2net: enable new Kconfig items in kernel configs (Brian Maly)  [Orabug: 29475071]
- benet: remove broken and unused macro (Lubomir Rintel)  [Orabug: 29475071]
- be2net: don't flip hw_features when VXLANs are added/deleted (Davide Caratti)  [Orabug: 29475071]
- be2net: Fix memory leak in be_cmd_get_profile_config() (Petr Oros)  [Orabug: 29475071]
- be2net: Use Kconfig flag to support for enabling/disabling adapters (Petr Oros)  [Orabug: 29475071]
- be2net: Mark expected switch fall-through (Gustavo A. R. Silva)  [Orabug: 29475071]
- be2net: fix spelling mistake 'seqence' -> 'sequence' (Colin Ian King)  [Orabug: 29475071]
- be2net: Update the driver version to 12.0.0.0 (Suresh Reddy)  [Orabug: 29475071]
- be2net: gather debug info and reset adapter (only for Lancer) on a tx-timeout (Suresh Reddy)  [Orabug: 29475071]
- be2net: move rss_flags field in rss_info to ensure proper alignment (Ivan Vecera)  [Orabug: 29475071]
- be2net: re-order fields in be_error_recovert to avoid hole (Ivan Vecera)  [Orabug: 29475071]
- be2net: remove unused tx_jiffies field from be_tx_stats (Ivan Vecera)  [Orabug: 29475071]
- be2net: move txcp field in be_tx_obj to eliminate holes in the struct (Ivan Vecera)  [Orabug: 29475071]
- be2net: reorder fields in be_eq_obj structure (Ivan Vecera)  [Orabug: 29475071]
- be2net: remove unused old custom busy-poll fields (Ivan Vecera)  [Orabug: 29475071]
- be2net: remove unused old AIC info (Ivan Vecera)  [Orabug: 29475071]
- be2net: Fix error detection logic for BE3 (Suresh Reddy)  [Orabug: 29475071]
- scsi: sd: Do not override max_sectors_kb sysfs setting (Martin K. Petersen)  [Orabug: 29596510]
- USB: serial: io_ti: fix div-by-zero in set_termios (Johan Hovold)  [Orabug: 29487834]  {CVE-2017-18360}
- bnxt_en: Drop oversize TX packets to prevent errors. (Michael Chan)  [Orabug: 29516462]
- x86/speculation: Read per-cpu value of x86_spec_ctrl_priv in x86_virt_spec_ctrl() (Alejandro Jimenez)  [Orabug: 29526401]
- x86/speculation: Keep enhanced IBRS on when prctl is used for SSBD control (Alejandro Jimenez)  [Orabug: 29526401]
- USB: hso: Fix OOB memory access in hso_probe/hso_get_config_data (Hui Peng)  [Orabug: 29605982]  {CVE-2018-19985} {CVE-2018-19985}
- swiotlb: save io_tlb_used to local variable before leaving critical section (Dongli Zhang)  [Orabug: 29637525]
- swiotlb: dump used and total slots when swiotlb buffer is full (Dongli Zhang)  [Orabug: 29637525]
- x86/bugs, kvm: don't miss SSBD when IBRS is in use. (Quentin Casasnovas)  [Orabug: 29642113]
- cifs: Fix use after free of a mid_q_entry (Shuning Zhang)  [Orabug: 29654888]
- binfmt_elf: switch to new creds when switching to new mm (Linus Torvalds)  [Orabug: 29677233]  {CVE-2019-11190}
- x86/microcode: Don't return error if microcode update is not needed (Boris Ostrovsky)  [Orabug: 29759756]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2019-May/008739.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2019-May/008740.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/17");
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
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  rm_kb_item(name:"Host/uptrack-uname-r");
  cve_list = make_list("CVE-2015-5327", "CVE-2017-18360", "CVE-2018-19985", "CVE-2019-11190");  
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for ELSA-2019-4642");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

kernel_major_minor = get_kb_item("Host/uname/major_minor");
if (empty_or_null(kernel_major_minor)) exit(1, "Unable to determine kernel major-minor level.");
expected_kernel_major_minor = "4.1";
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, "running kernel level " + expected_kernel_major_minor + ", it is running kernel level " + kernel_major_minor);

flag = 0;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-4.1.12-124.27.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-debug-4.1.12-124.27.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-debug-devel-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-debug-devel-4.1.12-124.27.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-devel-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-devel-4.1.12-124.27.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-doc-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-doc-4.1.12-124.27.1.el6uek")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-uek-firmware-4.1.12") && rpm_check(release:"EL6", cpu:"x86_64", reference:"kernel-uek-firmware-4.1.12-124.27.1.el6uek")) flag++;

if (rpm_exists(release:"EL7", rpm:"kernel-uek-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-4.1.12-124.27.1.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-4.1.12-124.27.1.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-devel-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-devel-4.1.12-124.27.1.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-devel-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-devel-4.1.12-124.27.1.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-doc-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-doc-4.1.12-124.27.1.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-firmware-4.1.12") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-firmware-4.1.12-124.27.1.el7uek")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
