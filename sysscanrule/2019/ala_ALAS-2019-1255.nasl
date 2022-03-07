#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2019-1255.
#

include("compat.inc");

if (description)
{
  script_id(127811);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/13 10:54:56");

  script_cve_id("CVE-2019-8320", "CVE-2019-8321", "CVE-2019-8322", "CVE-2019-8323", "CVE-2019-8324", "CVE-2019-8325");
  script_xref(name:"ALAS", value:"2019-1255");

  script_name(english:"Amazon Linux AMI : ruby20 / ruby21,ruby24 (ALAS-2019-1255)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An issue was discovered in RubyGems. The gem owner command outputs the
contents of the API response directly to stdout. Therefore, if the
response is crafted, escape sequence injection may
occur.(CVE-2019-8322)

An issue was discovered in RubyGems.
Gem::GemcutterUtilities#with_response may output the API response to
stdout as it is. Therefore, if the API side modifies the response,
escape sequence injection may occur.(CVE-2019-8323)

An issue was discovered in RubyGems. Since
Gem::UserInteraction#verbose calls say without escaping, escape
sequence injection is possible.(CVE-2019-8321)

A Directory Traversal issue was discovered in RubyGems. Before making
new directories or touching files (which now include path-checking
code for symlinks), it would delete the target destination. If that
destination was hidden behind a symlink, a malicious gem could delete
arbitrary files on the user's machine, presuming the attacker could
guess at paths. Given how frequently gem is run as sudo, and how
predictable paths are on modern systems (/tmp, /usr, etc.), this could
likely lead to data loss or an unusable system.(CVE-2019-8320)

An issue was discovered in RubyGems. A crafted gem with a multi-line
name is not handled correctly. Therefore, an attacker could inject
arbitrary code to the stub line of gemspec, which is eval-ed by code
in ensure_loadable_spec during the preinstall check.(CVE-2019-8324)

An issue was discovered in RubyGems. Since Gem::CommandManager#run
calls alert_error without escaping, escape sequence injection is
possible. (There are many ways to cause an error.)(CVE-2019-8325)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2019-1255.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update ruby20' to update your system.

Run 'yum update ruby21' to update your system.

Run 'yum update ruby24' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby20-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby21-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby21-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby21-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby21-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby21-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby24-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby24-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby24-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby24-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby24-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem20-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem20-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem20-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem21-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem21-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem21-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-did_you_mean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem24-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems20-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems21-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems24-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/13");
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
if (rpm_check(release:"ALA", reference:"ruby20-2.0.0.648-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby20-debuginfo-2.0.0.648-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby20-devel-2.0.0.648-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby20-doc-2.0.0.648-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby20-irb-2.0.0.648-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby20-libs-2.0.0.648-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby21-2.1.9-1.22.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby21-debuginfo-2.1.9-1.22.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby21-devel-2.1.9-1.22.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby21-doc-2.1.9-1.22.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby21-irb-2.1.9-1.22.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby21-libs-2.1.9-1.22.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby24-2.4.5-1.30.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby24-debuginfo-2.4.5-1.30.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby24-devel-2.4.5-1.30.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby24-doc-2.4.5-1.30.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby24-irb-2.4.5-1.30.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"ruby24-libs-2.4.5-1.30.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem20-bigdecimal-1.2.0-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem20-io-console-0.4.2-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem20-psych-2.0.0-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem21-bigdecimal-1.2.4-1.22.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem21-io-console-0.4.3-1.22.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem21-psych-2.0.5-1.22.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem24-bigdecimal-1.3.2-1.30.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem24-did_you_mean-1.1.0-1.30.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem24-io-console-0.4.6-1.30.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem24-json-2.0.4-1.30.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem24-psych-2.2.2-1.30.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygem24-xmlrpc-0.2.1-1.30.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems20-2.0.14.1-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems20-devel-2.0.14.1-1.32.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems21-2.2.5-1.22.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems21-devel-2.2.5-1.22.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems24-2.6.14.3-1.30.11.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"rubygems24-devel-2.6.14.3-1.30.11.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby20 / ruby20-debuginfo / ruby20-devel / ruby20-doc / ruby20-irb / etc");
}
