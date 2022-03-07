#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(127034);
  script_version("1.3");
  script_cvs_date("Date: 2019/08/12 17:35:39");

  script_cve_id("CVE-2019-2745", "CVE-2019-2762", "CVE-2019-2769", "CVE-2019-2786", "CVE-2019-2816", "CVE-2019-2842");

  script_name(english:"Scientific Linux Security Update : java-1.7.0-openjdk on SL7.x x86_64");
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

  - OpenJDK: Side-channel attack risks in Elliptic Curve
    (EC) cryptography (Security, 8208698) (CVE-2019-2745)

  - OpenJDK: Insufficient checks of suppressed exceptions in
    deserialization (Utilities, 8212328) (CVE-2019-2762)

  - OpenJDK: Unbounded memory allocation during
    deserialization in Collections (Utilities, 8213432)
    (CVE-2019-2769)

  - OpenJDK: Missing URL format validation (Networking,
    8221518) (CVE-2019-2816)

  - OpenJDK: Missing array bounds check in crypto providers
    (JCE, 8223511) (CVE-2019-2842)

  - OpenJDK: Insufficient restriction of privileges in
    AccessController (Security, 8216381) (CVE-2019-2786)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1907&L=SCIENTIFIC-LINUX-ERRATA&P=8583
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/25");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-1.7.0.231-2.6.19.1.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-accessibility-1.7.0.231-2.6.19.1.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.231-2.6.19.1.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-demo-1.7.0.231-2.6.19.1.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-devel-1.7.0.231-2.6.19.1.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-headless-1.7.0.231-2.6.19.1.el7_6")) flag++;
if (rpm_check(release:"SL7", reference:"java-1.7.0-openjdk-javadoc-1.7.0.231-2.6.19.1.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.7.0-openjdk-src-1.7.0.231-2.6.19.1.el7_6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
