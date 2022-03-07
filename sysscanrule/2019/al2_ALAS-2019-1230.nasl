#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1230.
#

include("compat.inc");

if (description)
{
  script_id(126383);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/02 12:46:52");

  script_cve_id("CVE-2018-1060", "CVE-2018-1061", "CVE-2018-20406", "CVE-2019-5010", "CVE-2019-9636");
  script_xref(name:"ALAS", value:"2019-1230");

  script_name(english:"Amazon Linux 2 : python (ALAS-2019-1230)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A NULL pointer dereference vulnerability was found in the certificate
parsing code in Python. This causes a denial of service to
applications when parsing specially crafted certificates. This
vulnerability is unlikely to be triggered if application enables
SSL/TLS certificate validation and accepts certificates only from
trusted root certificate authorities. (CVE-2019-5010)

Python 2.7.16 is affected by: Improper Handling of Unicode Encoding
(with an incorrect netloc) during NFKC normalization. The impact is:
Information disclosure (credentials, cookies, etc. that are cached
against a given hostname). The components are: urllib.parse.urlsplit,
urllib.parse.urlparse. The attack vector is: A specially crafted URL
could be incorrectly parsed to locate cookies or authentication data
and send that information to a different host than when parsed
correctly. (CVE-2019-9636)

A flaw was found in the way catastrophic backtracking was implemented
in python's pop3lib's apop() method. An attacker could use this flaw
to cause denial of service. (CVE-2018-1060)

Modules/_pickle.c in Python 2.7.16 has an integer overflow via a large
LONG_BINPUT value that is mishandled during a 'resize to twice the
size' attempt. This issue might cause memory exhaustion, but is only
relevant if the pickle format is used for serializing tens or hundreds
of gigabytes of data. (CVE-2018-20406)

A flaw was found in the way catastrophic backtracking was implemented
in python's difflib.IS_LINE_JUNK method. An attacker could use this
flaw to cause denial of service. (CVE-2018-1061)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1230.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update python' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/02");
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
if (rpm_check(release:"AL2", reference:"python-2.7.16-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"python-debug-2.7.16-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"python-debuginfo-2.7.16-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"python-devel-2.7.16-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"python-libs-2.7.16-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"python-test-2.7.16-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"python-tools-2.7.16-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"tkinter-2.7.16-1.amzn2.0.1")) flag++;

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
