#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(124753);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/10 10:59:32");

  script_cve_id("CVE-2019-11234", "CVE-2019-11235");

  script_name(english:"Scientific Linux Security Update : freeradius on SL7.x x86_64");
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

  - freeradius: eap-pwd: authentication bypass via an
    invalid curve attack (CVE-2019-11235)

  - freeradius: eap-pwd: fake authentication using
    reflection (CVE-2019-11234)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1905&L=SCIENTIFIC-LINUX-ERRATA&P=727
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/10");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"freeradius-3.0.13-10.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"freeradius-debuginfo-3.0.13-10.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"freeradius-devel-3.0.13-10.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"freeradius-doc-3.0.13-10.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"freeradius-krb5-3.0.13-10.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"freeradius-ldap-3.0.13-10.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"freeradius-mysql-3.0.13-10.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"freeradius-perl-3.0.13-10.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"freeradius-postgresql-3.0.13-10.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"freeradius-python-3.0.13-10.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"freeradius-sqlite-3.0.13-10.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"freeradius-unixODBC-3.0.13-10.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"freeradius-utils-3.0.13-10.el7_6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
