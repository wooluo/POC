#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2019-1207.
#

include("compat.inc");

if (description)
{
  script_id(125293);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/21  9:43:49");

  script_cve_id("CVE-2019-11023");
  script_xref(name:"ALAS", value:"2019-1207");

  script_name(english:"Amazon Linux AMI : graphviz (ALAS-2019-1207)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The agroot() function in cgraph\obj.c in libcgraph.a in Graphviz has a
NULL pointer dereference, as demonstrated by graphml2gv.
(CVE-2019-11023)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2019-1207.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update graphviz' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-R");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-graphs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-guile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-php54");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-python26");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-python27");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:graphviz-tcl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"graphviz-2.38.0-18.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphviz-R-2.38.0-18.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphviz-debuginfo-2.38.0-18.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphviz-devel-2.38.0-18.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphviz-doc-2.38.0-18.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphviz-gd-2.38.0-18.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphviz-graphs-2.38.0-18.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphviz-guile-2.38.0-18.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphviz-java-2.38.0-18.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphviz-lua-2.38.0-18.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphviz-perl-2.38.0-18.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphviz-php54-2.38.0-18.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphviz-python26-2.38.0-18.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphviz-python27-2.38.0-18.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphviz-ruby-2.38.0-18.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"graphviz-tcl-2.38.0-18.51.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "graphviz / graphviz-R / graphviz-debuginfo / graphviz-devel / etc");
}
