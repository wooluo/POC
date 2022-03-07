#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(125202);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/11 12:05:37");

  script_cve_id("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-11091");

  script_name(english:"Scientific Linux Security Update : kernel on SL6.x i386/x86_64 (MDSUM/RIDL) (MFBDS/RIDL/ZombieLoad) (MLPDS/RIDL) (MSBDS/Fallout)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security Fix(es) :

  - A flaw was found in the implementation of the 'fill
    buffer', a mechanism used by modern CPUs when a
    cache-miss is made on L1 CPU cache. If an attacker can
    generate a load operation that would create a page
    fault, the execution will continue speculatively with
    incorrect data from the fill buffer while the data is
    fetched from higher level caches. This response time can
    be measured to infer data in the fill buffer.
    (CVE-2018-12130)

  - Modern Intel microprocessors implement hardware-level
    micro- optimizations to improve the performance of
    writing data back to CPU caches. The write operation is
    split into STA (STore Address) and STD (STore Data)
    sub-operations. These sub-operations allow the processor
    to hand-off address generation logic into these
    sub-operations for optimized writes. Both of these
    sub-operations write to a shared distributed processor
    structure called the 'processor store buffer'. As a
    result, an unprivileged attacker could use this flaw to
    read private data resident within the CPU's processor
    store buffer. (CVE-2018-12126)

  - Microprocessors use a load port subcomponent to perform
    load operations from memory or IO. During a load
    operation, the load port receives data from the memory
    or IO subsystem and then provides the data to the CPU
    registers and operations in the CPUs pipelines. Stale
    load operations results are stored in the 'load port'
    table until overwritten by newer operations. Certain
    load-port operations triggered by an attacker can be
    used to reveal data about previous stale requests
    leaking data back to the attacker via a timing
    side-channel. (CVE-2018-12127)

  - Uncacheable memory on some microprocessors utilizing
    speculative execution may allow an authenticated user to
    potentially enable information disclosure via a side
    channel with local access. (CVE-2019-11091)

Bug Fix(es) :

  - aio O_DIRECT writes to non-page-aligned file locations
    on ext4 can result in the overlapped portion of the page
    containing zeros

  - Tolerate new s390x crypto hardware for migration"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1905&L=SCIENTIFIC-LINUX-ERRATA&P=3706
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/16");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-754.14.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-abi-whitelists-2.6.32-754.14.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-754.14.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-754.14.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-754.14.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-754.14.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-common-i686-2.6.32-754.14.2.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-754.14.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-754.14.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-754.14.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-754.14.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-754.14.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-754.14.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-754.14.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-754.14.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-754.14.2.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
