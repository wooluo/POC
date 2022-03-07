#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1667.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(126456);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/03 12:01:37");

  script_cve_id("CVE-2019-11459");

  script_name(english:"openSUSE Security Update : evince (openSUSE-2019-1667)");
  script_summary(english:"Check for the openSUSE-2019-1667 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for evince provides the following fixes: &#9; Security
issue fixed: &#9; 

  - CVE-2019-11459: Fixed an improper error handling in
    which could have led to use of uninitialized use of
    memory (bsc#1133037).&#9; 

Other issue addressed :

  - Removed Supplements from psdocument package, so that it
    isn't pulled in by default (bsc#1122794). This update
    was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1122794"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133037"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected evince packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-plugin-comicsdocument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-plugin-comicsdocument-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-plugin-djvudocument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-plugin-djvudocument-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-plugin-dvidocument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-plugin-dvidocument-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-plugin-pdfdocument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-plugin-pdfdocument-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-plugin-psdocument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-plugin-psdocument-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-plugin-tiffdocument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-plugin-tiffdocument-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-plugin-xpsdocument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:evince-plugin-xpsdocument-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libevdocument3-4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libevdocument3-4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libevview3-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libevview3-3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nautilus-evince");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nautilus-evince-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-EvinceDocument-3_0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:typelib-1_0-EvinceView-3_0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/03");
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
if (release !~ "^(SUSE15\.0|SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0 / 15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"evince-3.26.0+20180128.1bd86963-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"evince-debuginfo-3.26.0+20180128.1bd86963-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"evince-debugsource-3.26.0+20180128.1bd86963-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"evince-devel-3.26.0+20180128.1bd86963-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"evince-lang-3.26.0+20180128.1bd86963-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"evince-plugin-comicsdocument-3.26.0+20180128.1bd86963-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"evince-plugin-comicsdocument-debuginfo-3.26.0+20180128.1bd86963-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"evince-plugin-djvudocument-3.26.0+20180128.1bd86963-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"evince-plugin-djvudocument-debuginfo-3.26.0+20180128.1bd86963-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"evince-plugin-dvidocument-3.26.0+20180128.1bd86963-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"evince-plugin-dvidocument-debuginfo-3.26.0+20180128.1bd86963-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"evince-plugin-pdfdocument-3.26.0+20180128.1bd86963-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"evince-plugin-pdfdocument-debuginfo-3.26.0+20180128.1bd86963-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"evince-plugin-psdocument-3.26.0+20180128.1bd86963-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"evince-plugin-psdocument-debuginfo-3.26.0+20180128.1bd86963-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"evince-plugin-tiffdocument-3.26.0+20180128.1bd86963-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"evince-plugin-tiffdocument-debuginfo-3.26.0+20180128.1bd86963-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"evince-plugin-xpsdocument-3.26.0+20180128.1bd86963-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"evince-plugin-xpsdocument-debuginfo-3.26.0+20180128.1bd86963-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libevdocument3-4-3.26.0+20180128.1bd86963-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libevdocument3-4-debuginfo-3.26.0+20180128.1bd86963-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libevview3-3-3.26.0+20180128.1bd86963-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libevview3-3-debuginfo-3.26.0+20180128.1bd86963-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"nautilus-evince-3.26.0+20180128.1bd86963-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"nautilus-evince-debuginfo-3.26.0+20180128.1bd86963-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"typelib-1_0-EvinceDocument-3_0-3.26.0+20180128.1bd86963-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"typelib-1_0-EvinceView-3_0-3.26.0+20180128.1bd86963-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"evince-3.26.0+20180128.1bd86963-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"evince-debuginfo-3.26.0+20180128.1bd86963-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"evince-debugsource-3.26.0+20180128.1bd86963-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"evince-devel-3.26.0+20180128.1bd86963-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"evince-lang-3.26.0+20180128.1bd86963-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"evince-plugin-comicsdocument-3.26.0+20180128.1bd86963-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"evince-plugin-comicsdocument-debuginfo-3.26.0+20180128.1bd86963-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"evince-plugin-djvudocument-3.26.0+20180128.1bd86963-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"evince-plugin-djvudocument-debuginfo-3.26.0+20180128.1bd86963-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"evince-plugin-dvidocument-3.26.0+20180128.1bd86963-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"evince-plugin-dvidocument-debuginfo-3.26.0+20180128.1bd86963-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"evince-plugin-pdfdocument-3.26.0+20180128.1bd86963-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"evince-plugin-pdfdocument-debuginfo-3.26.0+20180128.1bd86963-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"evince-plugin-psdocument-3.26.0+20180128.1bd86963-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"evince-plugin-psdocument-debuginfo-3.26.0+20180128.1bd86963-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"evince-plugin-tiffdocument-3.26.0+20180128.1bd86963-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"evince-plugin-tiffdocument-debuginfo-3.26.0+20180128.1bd86963-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"evince-plugin-xpsdocument-3.26.0+20180128.1bd86963-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"evince-plugin-xpsdocument-debuginfo-3.26.0+20180128.1bd86963-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libevdocument3-4-3.26.0+20180128.1bd86963-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libevdocument3-4-debuginfo-3.26.0+20180128.1bd86963-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libevview3-3-3.26.0+20180128.1bd86963-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libevview3-3-debuginfo-3.26.0+20180128.1bd86963-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nautilus-evince-3.26.0+20180128.1bd86963-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"nautilus-evince-debuginfo-3.26.0+20180128.1bd86963-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"typelib-1_0-EvinceDocument-3_0-3.26.0+20180128.1bd86963-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"typelib-1_0-EvinceView-3_0-3.26.0+20180128.1bd86963-lp151.4.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "evince / evince-debuginfo / evince-debugsource / evince-devel / etc");
}
