#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1190.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(124017);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/30 14:30:16");

  script_cve_id("CVE-2019-0196", "CVE-2019-0197", "CVE-2019-0211", "CVE-2019-0217", "CVE-2019-0220");

  script_name(english:"openSUSE Security Update : apache2 (openSUSE-2019-1190)");
  script_summary(english:"Check for the openSUSE-2019-1190 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for apache2 fixes the following issues :

  - CVE-2019-0220: The Apache HTTP server did not use a
    consistent strategy for URL normalization throughout all
    of its components. In particular, consecutive slashes
    were not always collapsed. Attackers could potentially
    abuse these inconsistencies to by-pass access control
    mechanisms and thus gain unauthorized access to
    protected parts of the service. [bsc#1131241]

  - CVE-2019-0217: A race condition in Apache's
    'mod_auth_digest' when running in a threaded server
    could have allowed users with valid credentials to
    authenticate using another username, bypassing
    configured access control restrictions. [bsc#1131239]

  - CVE-2019-0211: A flaw in the Apache HTTP Server allowed
    less-privileged child processes or threads to execute
    arbitrary code with the privileges of the parent
    process. Attackers with control over CGI scripts or
    extension modules run by the server could have abused
    this issue to potentially gain super user privileges.
    [bsc#1131233]

  - CVE-2019-0197: When HTTP/2 support was enabled in the
    Apache server for a 'http' host or H2Upgrade was enabled
    for h2 on a 'https' host, an Upgrade request from
    http/1.1 to http/2 that was not the first request on a
    connection could lead to a misconfiguration and crash.
    This issue could have been abused to mount a
    denial-of-service attack. Servers that never enabled the
    h2 protocol or that only enabled it for https: and did
    not configure the 'H2Upgrade on' are unaffected.
    [bsc#1131245]

  - CVE-2019-0196: Through specially crafted network input
    the Apache's http/2 request handler could be lead to
    access previously freed memory while determining the
    method of a request. This resulted in the request being
    misclassified and thus being processed incorrectly.
    [bsc#1131237]

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131233"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131237"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131239"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131245"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected apache2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-event");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-event-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-example-pages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-prefork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-prefork-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-worker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:apache2-worker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/12");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"apache2-2.4.23-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-debuginfo-2.4.23-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-debugsource-2.4.23-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-devel-2.4.23-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-event-2.4.23-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-event-debuginfo-2.4.23-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-example-pages-2.4.23-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-prefork-2.4.23-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-prefork-debuginfo-2.4.23-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-utils-2.4.23-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-utils-debuginfo-2.4.23-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-worker-2.4.23-45.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"apache2-worker-debuginfo-2.4.23-45.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "apache2 / apache2-debuginfo / apache2-debugsource / apache2-devel / etc");
}
