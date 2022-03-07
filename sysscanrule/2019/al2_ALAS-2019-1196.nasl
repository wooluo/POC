#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1196.
#

include("compat.inc");

if (description)
{
  script_id(124302);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/26  9:36:41");

  script_cve_id("CVE-2019-3816");
  script_xref(name:"ALAS", value:"2019-1196");

  script_name(english:"Amazon Linux 2 : openwsman (ALAS-2019-1196)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Earlier versions of Openwsman are vulnerable to arbitrary file
disclosure because the working directory of openwsmand daemon was set
to root directory. A remote, unauthenticated attacker can exploit this
vulnerability by sending a specially crafted HTTP request to openwsman
server. (CVE-2019-3816)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1196.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update openwsman' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwsman-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libwsman1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openwsman-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openwsman-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openwsman-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openwsman-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openwsman-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openwsman-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/26");
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
if (rpm_check(release:"AL2", reference:"libwsman-devel-2.6.3-6.git4391e5c.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"libwsman1-2.6.3-6.git4391e5c.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"openwsman-client-2.6.3-6.git4391e5c.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"openwsman-debuginfo-2.6.3-6.git4391e5c.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"openwsman-perl-2.6.3-6.git4391e5c.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"openwsman-python-2.6.3-6.git4391e5c.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"openwsman-ruby-2.6.3-6.git4391e5c.amzn2")) flag++;
if (rpm_check(release:"AL2", reference:"openwsman-server-2.6.3-6.git4391e5c.amzn2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libwsman-devel / libwsman1 / openwsman-client / openwsman-debuginfo / etc");
}
