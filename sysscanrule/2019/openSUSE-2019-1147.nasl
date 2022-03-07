#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1147.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(123776);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/05 15:04:41");

  script_cve_id("CVE-2019-1543");

  script_name(english:"openSUSE Security Update : openssl-1_1 (openSUSE-2019-1147)");
  script_summary(english:"Check for the openSUSE-2019-1147 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for openssl-1_1 (OpenSSL Security Advisory [6 March 2019])
fixes the following issues :

Security issue fixed: &#9; 

  - CVE-2019-1543: Fixed an implementation error in
    ChaCha20-Poly1305 where it was allowed to set IV with
    more than 12 bytes (bsc#1128189). Other issues 
addressed :

  - Fixed a segfault in openssl speed when an unknown
    algorithm is passed (bsc#1125494).

  - Correctly skipped binary curves in openssl speed to
    avoid spitting errors (bsc#1116833).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1116833"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1128189"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl-1_1 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl-1_1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopenssl1_1-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl-1_1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl-1_1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssl-1_1-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"libopenssl-1_1-devel-1.1.0i-lp150.3.22.3") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libopenssl1_1-1.1.0i-lp150.3.22.3") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libopenssl1_1-debuginfo-1.1.0i-lp150.3.22.3") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libopenssl1_1-hmac-1.1.0i-lp150.3.22.3") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"openssl-1_1-1.1.0i-lp150.3.22.3") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"openssl-1_1-debuginfo-1.1.0i-lp150.3.22.3") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"openssl-1_1-debugsource-1.1.0i-lp150.3.22.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libopenssl-1_1-devel / libopenssl1_1 / libopenssl1_1-debuginfo / etc");
}