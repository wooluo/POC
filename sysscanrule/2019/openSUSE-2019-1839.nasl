#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1839.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(127742);
  script_version("1.3");
  script_cvs_date("Date: 2019/08/20 11:58:13");

  script_cve_id("CVE-2019-11358", "CVE-2019-12308", "CVE-2019-12781", "CVE-2019-14232", "CVE-2019-14233", "CVE-2019-14234", "CVE-2019-14235");

  script_name(english:"openSUSE Security Update : python-Django (openSUSE-2019-1839)");
  script_summary(english:"Check for the openSUSE-2019-1839 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for python-Django fixes the following issues :

Security issues fixed :

&#9; - CVE-2019-11358: Fixed prototype pollution.

  - CVE-2019-12308: Fixed XSS in AdminURLFieldWidget
    (bsc#1136468)

  - CVE-2019-12781: Fixed incorrect HTTP detection with
    reverse-proxy connecting via HTTPS (bsc#1139945).

  - CVE-2019-14232: Fixed denial-of-service possibility in
    ``django.utils.text.Truncator`` (bsc#1142880).

  - CVE-2019-14233: Fixed denial-of-service possibility in
    ``strip_tags()`` (bsc#1142882).

  - CVE-2019-14234: Fixed SQL injection possibility in key
    and index lookups for ``JSONField``/``HStoreField``
    (bsc#1142883).

  - CVE-2019-14235: Fixed potential memory exhaustion in
    ``django.utils.encoding.uri_to_iri()`` (bsc#1142885).

Non-security issues fixed :

  - Fixed a migration crash on PostgreSQL when adding a
    check constraint with a contains lookup on
    DateRangeField or DateTimeRangeField, if the right hand
    side of an expression is the same type."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136468"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1139945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142880"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142882"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142883"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1142885"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python-Django package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-Django");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"python3-Django-2.2.4-lp151.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python3-Django");
}
