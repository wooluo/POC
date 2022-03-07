#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1249.
#

include("compat.inc");

if (description)
{
  script_id(126961);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/24  9:40:16");

  script_cve_id("CVE-2019-8322", "CVE-2019-8323", "CVE-2019-8324", "CVE-2019-8325");
  script_xref(name:"ALAS", value:"2019-1249");

  script_name(english:"Amazon Linux 2 : ruby (ALAS-2019-1249)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An issue was discovered in RubyGems 2.6 and later through 3.0.2. The
gem owner command outputs the contents of the API response directly to
stdout. Therefore, if the response is crafted, escape sequence
injection may occur. (CVE-2019-8322)

An issue was discovered in RubyGems 2.6 and later through 3.0.2.
Gem::GemcutterUtilities#with_response may output the API response to
stdout as it is. Therefore, if the API side modifies the response,
escape sequence injection may occur. (CVE-2019-8323)

An issue was discovered in RubyGems 2.6 and later through 3.0.2. Since
Gem::CommandManager#run calls alert_error without escaping, escape
sequence injection is possible. (There are many ways to cause an
error.) (CVE-2019-8325)

An issue was discovered in RubyGems 2.6 and later through 3.0.2. A
crafted gem with a multi-line name is not handled correctly.
Therefore, an attacker could inject arbitrary code to the stub line of
gemspec, which is eval-ed by code in ensure_loadable_spec during the
preinstall check. (CVE-2019-8324)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1249.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update ruby' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:rubygems-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/24");
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
if (rpm_check(release:"AL2", reference:"ruby-2.0.0.648-35.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"ruby-debuginfo-2.0.0.648-35.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"ruby-devel-2.0.0.648-35.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"ruby-doc-2.0.0.648-35.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"ruby-irb-2.0.0.648-35.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"ruby-libs-2.0.0.648-35.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"ruby-tcltk-2.0.0.648-35.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"rubygem-bigdecimal-1.2.0-35.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"rubygem-io-console-0.4.2-35.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"rubygem-json-1.7.7-35.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"rubygem-minitest-4.3.2-35.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"rubygem-psych-2.0.0-35.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"rubygem-rake-0.9.6-35.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"rubygem-rdoc-4.0.0-35.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"rubygems-2.0.14.1-35.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"rubygems-devel-2.0.14.1-35.amzn2.0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby / ruby-debuginfo / ruby-devel / ruby-doc / ruby-irb / etc");
}
