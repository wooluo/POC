#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2019-4708.
#

include("compat.inc");

if (description)
{
  script_id(126557);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/24  9:40:20");

  script_cve_id("CVE-2019-6133");

  script_name(english:"Oracle Linux 7 : Unbreakable Enterprise kernel (ELSA-2019-4708)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Description of changes:

[4.14.35-1902.3.1.el7uek]
- x86/platform/UV: Mark tsc_check_sync as an init function (<A HREF='https://oss.oracle.com/mailman/listinfo/el-errata'>mike.travis at hpe.com</A>)  [Orabug: 29701029]
- mm, page_alloc: check for max order in hot path (Michal Hocko)  [Orabug: 29924411]
- net/mlx5: FW tracer, Enable tracing (Feras Daoud)  [Orabug: 29717200]
- net/mlx5: FW tracer, parse traces and kernel tracing support (Feras Daoud)  [Orabug: 29717200]
- net/mlx5: FW tracer, events handling (Feras Daoud)  [Orabug: 29717200]
- net/mlx5: FW tracer, register log buffer memory key (Saeed Mahameed)  [Orabug: 29717200]
- net/mlx5: FW tracer, create trace buffer and copy strings database (Feras Daoud)  [Orabug: 29717200]
- net/mlx5: FW tracer, implement tracer logic (Feras Daoud)  [Orabug: 29717200]
- net/mlx5: FW tracer, add hardware structures (Feras Daoud)  [Orabug: 29717200]
- net/mlx5: Mkey creation command adjustments (Ariel Levkovich)  [Orabug: 29717200]
- rds: Incorrect locking in rds_tcp_conn_path_shutdown() (Ka-Cheong Poon)  [Orabug: 29814108]
- rds: Add per namespace RDS/TCP accept work queue (Ka-Cheong Poon)  [Orabug: 29814108]
- rds: ib: Fix dereference of conn when NULL and cleanup thereof (H&aring kon Bugge)  [Orabug: 29924845]
- AMD: Change CONFIG_EDAC_DECODE_MCE to built-in (George Kennedy)  [Orabug: 29926109]
- watchdog: sp5100_tco: Add support for recent FCH versions (Guenter Roeck)  [Orabug: 29933621]
- watchdog: sp5100-tco: Abort if watchdog is disabled by hardware (Guenter Roeck)  [Orabug: 29933621]
- watchdog: sp5100_tco: Use bit operations (Guenter Roeck)  [Orabug: 29933621]
- watchdog: sp5100_tco: Convert to use watchdog subsystem (Guenter Roeck)  [Orabug: 29933621]
- watchdog: sp5100_tco: Clean up function and variable names (Guenter Roeck)  [Orabug: 29933621]
- watchdog: sp5100_tco: Use dev_ print functions where possible (Guenter Roeck)  [Orabug: 29933621]
- watchdog: sp5100_tco: Match PCI device early (Guenter Roeck)  [Orabug: 29933621]
- watchdog: sp5100_tco: Clean up sp5100_tco_setupdevice (Guenter Roeck)  [Orabug: 29933621]
- watchdog: sp5100_tco: Use standard error codes (Guenter Roeck)  [Orabug: 29933621]
- watchdog: sp5100_tco: Use request_muxed_region where possible (Guenter Roeck)  [Orabug: 29933621]
- watchdog: sp5100_tco: Always use SP5100_IO_PM_{INDEX_REG,DATA_REG} (Guenter Roeck)  [Orabug: 29933621]
- i2c: piix4: Use request_muxed_region (Guenter Roeck)  [Orabug: 29933621]
- i2c: piix4: Use usleep_range() (Guenter Roeck)  [Orabug: 29933621]
- i2c: piix4: Fix port number check on release (Jean Delvare)  [Orabug: 29933621]
- scsi: smartpqi: correct lun reset issues (Kevin Barnett)  [Orabug: 29939095]

[4.14.35-1902.3.0.el7uek]
- nvme.h: fixup ANA group descriptor format (Hannes Reinecke)  [Orabug: 29750813]
- nvme: validate cntlid during controller initialisation (Christoph Hellwig)  [Orabug: 29750813]
- nvme: change locking for the per-subsystem controller list (Christoph Hellwig)  [Orabug: 29750813]
- net/mlx5e: Disable ODP capability advertizing and close kernel ODP flows (Qing Huang)  [Orabug: 29786503]
- EDAC/amd64: Adjust printed chip select sizes when interleaved (Yazen Ghannam)  [Orabug: 29861840]
- EDAC/amd64: Support more than two controllers for chip select handling (Yazen Ghannam)  [Orabug: 29861840]
- EDAC/amd64: Recognize x16 symbol size (Yazen Ghannam)  [Orabug: 29861840]
- EDAC/amd64: Set maximum channel layer size depending on family (Yazen Ghannam)  [Orabug: 29861840]
- EDAC/amd64: Support more than two Unified Memory Controllers (Yazen Ghannam)  [Orabug: 29861840]
- EDAC/amd64: Use a macro for iterating over Unified Memory Controllers (Yazen Ghannam)  [Orabug: 29861840]
- EDAC/amd64: Add Family 17h Model 30h PCI IDs (Yazen Ghannam)  [Orabug: 29861840]
- EDAC, amd64: Add Family 17h, models 10h-2fh support (Michael Jin)  [Orabug: 29861840]
- libnvdimm/namespace: Fix label tracking error (Dan Williams)  [Orabug: 29839902]
- fork: record start_time late (David Herrmann)  [Orabug: 29850579]  {CVE-2019-6133}
- IB/mlx5: Removed an empty file introduced by Mellanox backport (Qing Huang)  [Orabug: 29891479]
- config: enable PSI (Tom Hromatka)  [Orabug: 29896487]
- net/mlx5: Set FW pre-init timeout to 120k (Yuval Shaia)  [Orabug: 29906258]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2019-July/008879.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected unbreakable enterprise kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-uek-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/09");
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
  cve_list = make_list("CVE-2019-6133");  
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for ELSA-2019-4708");
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
if (rpm_exists(release:"EL7", rpm:"kernel-uek-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-4.14.35-1902.3.1.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-4.14.35-1902.3.1.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-debug-devel-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-debug-devel-4.14.35-1902.3.1.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-devel-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-devel-4.14.35-1902.3.1.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-doc-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-doc-4.14.35-1902.3.1.el7uek")) flag++;
if (rpm_exists(release:"EL7", rpm:"kernel-uek-tools-4.14.35") && rpm_check(release:"EL7", cpu:"x86_64", reference:"kernel-uek-tools-4.14.35-1902.3.1.el7uek")) flag++;


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
