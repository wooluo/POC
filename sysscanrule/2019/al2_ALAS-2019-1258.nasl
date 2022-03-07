#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1258.
#

include("compat.inc");

if (description)
{
  script_id(127462);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2019-10160");
  script_xref(name:"ALAS", value:"2019-1258");

  script_name(english:"Amazon Linux 2 : python (ALAS-2019-1258)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A security regression of CVE-2019-9636 was discovered in python, which
still allows an attacker to exploit CVE-2019-9636 by abusing the user
and password parts of a URL. When an application parses user-supplied
URLs to store cookies, authentication credentials, or other kind of
information, it is possible for an attacker to provide specially
crafted URLs to make the application locate host-related information
(e.g. cookies, authentication data) and send them to a different host
than where it should, unlike if the URLs had been correctly parsed.
The result of an attack may vary based on the application.
(CVE-2019-10160)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1258.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update python' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:python-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:tkinter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"python-2.7.16-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"python-debug-2.7.16-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"python-debuginfo-2.7.16-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"python-devel-2.7.16-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"python-libs-2.7.16-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"python-test-2.7.16-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"python-tools-2.7.16-2.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"tkinter-2.7.16-2.amzn2.0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python / python-debug / python-debuginfo / python-devel / etc");
}