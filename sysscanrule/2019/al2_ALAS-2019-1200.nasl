#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1200.
#

include("compat.inc");

if (description)
{
  script_id(125287);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/21  9:43:49");

  script_cve_id("CVE-2019-3877", "CVE-2019-3878");
  script_xref(name:"ALAS", value:"2019-1200");

  script_name(english:"Amazon Linux 2 : mod_auth_mellon (ALAS-2019-1200)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability was found in a previous version of mod_auth_mellon. An
open redirect in the logout URL allows requests with backslashes to
pass through by assuming that it is a relative URL, while the browsers
silently convert backslash characters into forward slashes treating
them as an absolute URL. This mismatch allows an attacker to bypass
the redirect URL validation logic in apr_uri_parse
function.(CVE-2019-3877)

A vulnerability was found in mod_auth_mellon. If Apache is configured
as a reverse proxy and mod_auth_mellon is configured to only let
through authenticated users (with the require valid-user directive),
adding special HTTP headers that are normally used to start the
special SAML ECP (non-browser based) can be used to bypass
authentication.(CVE-2019-3878)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1200.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update mod_auth_mellon' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_auth_mellon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_auth_mellon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod_auth_mellon-diagnostics");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/26");
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
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"mod_auth_mellon-0.14.0-2.amzn2.4")) flag++;
if (rpm_check(release:"AL2", reference:"mod_auth_mellon-debuginfo-0.14.0-2.amzn2.4")) flag++;
if (rpm_check(release:"AL2", reference:"mod_auth_mellon-diagnostics-0.14.0-2.amzn2.4")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod_auth_mellon / mod_auth_mellon-debuginfo / etc");
}
