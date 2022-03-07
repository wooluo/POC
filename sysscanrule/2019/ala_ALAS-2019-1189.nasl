#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2019-1189.
#

include("compat.inc");

if (description)
{
  script_id(123958);
  script_version("1.5");
  script_cvs_date("Date: 2019/08/12 17:35:38");

  script_cve_id("CVE-2019-0196", "CVE-2019-0197", "CVE-2019-0211", "CVE-2019-0215", "CVE-2019-0217", "CVE-2019-0220");
  script_xref(name:"ALAS", value:"2019-1189");

  script_name(english:"Amazon Linux AMI : httpd24 (ALAS-2019-1189)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"In Apache HTTP Server with MPM event, worker or prefork, code
executing in less-privileged child processes or threads (including
scripts executed by an in-process scripting interpreter) could execute
arbitrary code with the privileges of the parent process (usually
root) by manipulating the scoreboard. (CVE-2019-0211)

A vulnerability was found in Apache HTTP Server 2.4.0 to 2.4.38. When
the path component of a request URL contains multiple consecutive
slashes ('/'), directives such as LocationMatch and RewriteRule must
account for duplicates in regular expressions while other aspects of
the servers processing will implicitly collapse them.(CVE-2019-0220)

In Apache HTTP Server 2.4 releases 2.4.37 and 2.4.38, a bug in mod_ssl
when using per-location client certificate verification with TLSv1.3
allowed a client to bypass configured access control
restrictions.(CVE-2019-0215)

A vulnerability was found in Apache HTTP Server 2.4.17 to 2.4.38.
Using fuzzed network input, the http/2 request handling could be made
to access freed memory in string comparison when determining the
method of a request and thus process the request
incorrectly.(CVE-2019-0196)

A vulnerability was found in Apache HTTP Server 2.4.34 to 2.4.38. When
HTTP/2 was enabled for a http: host or H2Upgrade was enabled for h2 on
a https: host, an Upgrade request from http/1.1 to http/2 that was not
the first request on a connection could lead to a misconfiguration and
crash. Server that never enabled the h2 protocol or that only enabled
it for https: and did not set 'H2Upgrade on' are unaffected by this
issue.(CVE-2019-0197)

A race condition was found in mod_auth_digest when the web server was
running in a threaded MPM configuration. It could allow a user with
valid credentials to authenticate using another username, bypassing
configured access control restrictions.(CVE-2019-0217)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2019-1189.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update httpd24' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:httpd24-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_md");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:mod24_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/10");
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
if (rpm_check(release:"ALA", reference:"httpd24-2.4.39-1.87.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-debuginfo-2.4.39-1.87.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-devel-2.4.39-1.87.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-manual-2.4.39-1.87.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"httpd24-tools-2.4.39-1.87.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_ldap-2.4.39-1.87.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_md-2.4.39-1.87.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_proxy_html-2.4.39-1.87.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_session-2.4.39-1.87.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"mod24_ssl-2.4.39-1.87.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd24 / httpd24-debuginfo / httpd24-devel / httpd24-manual / etc");
}
