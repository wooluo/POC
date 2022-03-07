#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2019-1246.
#

include("compat.inc");

if (description)
{
  script_id(127074);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/26 16:46:12");

  script_cve_id("CVE-2019-12749");
  script_xref(name:"ALAS", value:"2019-1246");

  script_name(english:"Amazon Linux AMI : dbus (ALAS-2019-1246)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"dbus as used in DBusServer, allows cookie spoofing because of symlink
mishandling in the reference implementation of DBUS_COOKIE_SHA1 in the
libdbus library. (This only affects the DBUS_COOKIE_SHA1
authentication mechanism.) A malicious client with write access to its
own home directory could manipulate a ~/.dbus-keyrings symlink to
cause a DBusServer with a different uid to read and write in
unintended locations. In the worst case, this could result in the
DBusServer reusing a cookie that is known to the malicious client, and
treating that cookie as evidence that a subsequent client connection
came from an attacker-chosen uid, allowing authentication bypass.
(CVE-2019-12749)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2019-1246.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update dbus' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dbus-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dbus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dbus-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dbus-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/26");
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
if (rpm_check(release:"ALA", reference:"dbus-1.6.12-14.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"dbus-debuginfo-1.6.12-14.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"dbus-devel-1.6.12-14.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"dbus-doc-1.6.12-14.29.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"dbus-libs-1.6.12-14.29.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dbus / dbus-debuginfo / dbus-devel / dbus-doc / dbus-libs");
}
