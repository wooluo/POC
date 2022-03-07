#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1459.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(125532);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/29 10:47:05");

  script_cve_id("CVE-2019-11023");

  script_name(english:"openSUSE Security Update : graphviz (openSUSE-2019-1459)");
  script_summary(english:"Check for the openSUSE-2019-1459 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for graphviz fixes the following issues :

Security issue fixed :

  - CVE-2019-11023: Fixed a denial of service vulnerability,
    which was caused by a NULL pointer dereference in
    agroot() (bsc#1132091).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1132091"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected graphviz packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-addons-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-addons-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-gd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-guile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-guile-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-gvedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-gvedit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-java-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-lua-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-php-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-plugins-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-plugins-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-smyrna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-smyrna-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:graphviz-tcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgraphviz6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgraphviz6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/29");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"graphviz-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-addons-debuginfo-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-addons-debugsource-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-debuginfo-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-debugsource-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-devel-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-gd-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-gd-debuginfo-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-gnome-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-gnome-debuginfo-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-guile-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-guile-debuginfo-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-gvedit-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-gvedit-debuginfo-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-java-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-java-debuginfo-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-lua-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-lua-debuginfo-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-perl-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-perl-debuginfo-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-php-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-php-debuginfo-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-plugins-core-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-plugins-core-debuginfo-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-python-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-python-debuginfo-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-ruby-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-ruby-debuginfo-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-smyrna-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-smyrna-debuginfo-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-tcl-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"graphviz-tcl-debuginfo-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgraphviz6-2.40.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libgraphviz6-debuginfo-2.40.1-lp150.5.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "graphviz-addons-debuginfo / graphviz-addons-debugsource / etc");
}
