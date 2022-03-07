#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-344.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(122941);
  script_version("1.1");
  script_cvs_date("Date: 2019/03/19 11:02:10");

  script_cve_id("CVE-2019-3811");

  script_name(english:"openSUSE Security Update : sssd (openSUSE-2019-344)");
  script_summary(english:"Check for the openSUSE-2019-344 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for sssd fixes the following issues :

Security vulnerability addresed :

  - CVE-2019-3811: Fix fallback_homedir returning '/' for
    empty home directories (bsc#1121759)

Other bug fixes and changes :

  - Install logrotate configuration (bsc#1004220)

  - Align systemd service file with upstream, run
    interactive and change service type to notify
    (bsc#1120852)

  - Fix sssd not starting in foreground mode (bsc#1125277)

  - Strip whitespaces in netgroup triples (bsc#1087320)

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120852"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121759"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1125277"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sssd packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:adcli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:adcli-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:adcli-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipa_hbac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipa_hbac0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnfsidmap-sss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnfsidmap-sss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_certmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_certmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_certmap0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_idmap0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_nss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_nss_idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_nss_idmap0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_simpleifp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_simpleifp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsss_simpleifp0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-ipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-ipa_hbac-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-sss-murmur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-sss-murmur-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-sss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-sss_nss_idmap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-sssd-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-sssd-config-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-ad-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-dbus-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-ipa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-krb5-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-proxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-wbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-wbclient-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-wbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-winbind-idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:sssd-winbind-idmap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/19");
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

if ( rpm_check(release:"SUSE15.0", reference:"adcli-0.8.2-lp150.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"adcli-debuginfo-0.8.2-lp150.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"adcli-debugsource-0.8.2-lp150.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libipa_hbac-devel-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libipa_hbac0-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libipa_hbac0-debuginfo-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libnfsidmap-sss-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libnfsidmap-sss-debuginfo-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libsss_certmap-devel-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libsss_certmap0-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libsss_certmap0-debuginfo-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libsss_idmap-devel-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libsss_idmap0-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libsss_idmap0-debuginfo-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libsss_nss_idmap-devel-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libsss_nss_idmap0-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libsss_nss_idmap0-debuginfo-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libsss_simpleifp-devel-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libsss_simpleifp0-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"libsss_simpleifp0-debuginfo-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-ipa_hbac-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-ipa_hbac-debuginfo-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-sss-murmur-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-sss-murmur-debuginfo-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-sss_nss_idmap-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-sss_nss_idmap-debuginfo-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-sssd-config-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"python3-sssd-config-debuginfo-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"sssd-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"sssd-ad-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"sssd-ad-debuginfo-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"sssd-dbus-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"sssd-dbus-debuginfo-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"sssd-debuginfo-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"sssd-debugsource-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"sssd-ipa-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"sssd-ipa-debuginfo-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"sssd-krb5-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"sssd-krb5-common-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"sssd-krb5-common-debuginfo-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"sssd-krb5-debuginfo-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"sssd-ldap-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"sssd-ldap-debuginfo-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"sssd-proxy-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"sssd-proxy-debuginfo-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"sssd-tools-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"sssd-tools-debuginfo-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"sssd-wbclient-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"sssd-wbclient-debuginfo-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"sssd-wbclient-devel-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"sssd-winbind-idmap-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"sssd-winbind-idmap-debuginfo-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"sssd-32bit-1.16.1-lp150.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"sssd-32bit-debuginfo-1.16.1-lp150.2.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "adcli / adcli-debuginfo / adcli-debugsource / libipa_hbac-devel / etc");
}
