#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(122392);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/04 11:19:02");

  script_cve_id("CVE-2019-6454");

  script_name(english:"Scientific Linux Security Update : systemd on SL7.x x86_64");
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

  - systemd: Insufficient input validation in
    bus_process_object() resulting in PID 1 crash
    (CVE-2019-6454)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1902&L=SCIENTIFIC-LINUX-ERRATA&P=6852
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/22");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libgudev1-219-62.el7_6.5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libgudev1-devel-219-62.el7_6.5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"systemd-219-62.el7_6.5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"systemd-debuginfo-219-62.el7_6.5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"systemd-devel-219-62.el7_6.5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"systemd-journal-gateway-219-62.el7_6.5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"systemd-libs-219-62.el7_6.5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"systemd-networkd-219-62.el7_6.5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"systemd-python-219-62.el7_6.5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"systemd-resolved-219-62.el7_6.5")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"systemd-sysv-219-62.el7_6.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
