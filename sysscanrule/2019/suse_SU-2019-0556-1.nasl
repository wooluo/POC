#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:0556-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(122665);
  script_version("1.1");
  script_cvs_date("Date: 2019/03/07 17:16:14");

  script_cve_id("CVE-2018-10852", "CVE-2019-3811");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : sssd (SUSE-SU-2019:0556-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for sssd fixes the following issues :

Security vulnerabilities addressed :

Fix fallback_homedir returning '/' for empty home directories
(CVE-2019-3811) (bsc#1121759)

Create sockets with right permissions (bsc#1098377, CVE-2018-10852)

Other bug fixes and changes: Install logrotate configuration
(bsc#1004220)

Strip whitespaces in netgroup triples (bsc#1087320)

Align systemd service file with upstream

  - Run interactive and change service type to notify
    (bsc#1120852)

  - Replace deprecated '-f' and use '--logger'

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1004220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1087320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1098377"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1120852"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1121759"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-10852/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-3811/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20190556-1/
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP4:zypper in -t
patch SUSE-SLE-SDK-12-SP4-2019-556=1

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2019-556=1

SUSE Linux Enterprise Desktop 12-SP4:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP4-2019-556=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libipa_hbac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libipa_hbac0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_certmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_certmap0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_idmap0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_nss_idmap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_nss_idmap0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_simpleifp0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsss_simpleifp0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-sssd-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-sssd-config-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-ad-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-ipa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-krb5-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-krb5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-ldap-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-proxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:sssd-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP4", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"libipa_hbac0-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libipa_hbac0-debuginfo-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsss_certmap0-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsss_certmap0-debuginfo-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsss_idmap0-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsss_idmap0-debuginfo-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsss_nss_idmap0-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsss_nss_idmap0-debuginfo-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsss_simpleifp0-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"libsss_simpleifp0-debuginfo-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-sssd-config-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-sssd-config-debuginfo-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"sssd-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"sssd-ad-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"sssd-ad-debuginfo-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"sssd-debuginfo-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"sssd-debugsource-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"sssd-ipa-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"sssd-ipa-debuginfo-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"sssd-krb5-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"sssd-krb5-common-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"sssd-krb5-common-debuginfo-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"sssd-krb5-debuginfo-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"sssd-ldap-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"sssd-ldap-debuginfo-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"sssd-proxy-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"sssd-proxy-debuginfo-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"sssd-tools-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"sssd-tools-debuginfo-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"sssd-32bit-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"sssd-debuginfo-32bit-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libipa_hbac0-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libipa_hbac0-debuginfo-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libsss_certmap0-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libsss_certmap0-debuginfo-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libsss_idmap0-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libsss_idmap0-debuginfo-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libsss_nss_idmap0-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libsss_nss_idmap0-debuginfo-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libsss_simpleifp0-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"libsss_simpleifp0-debuginfo-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python-sssd-config-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"python-sssd-config-debuginfo-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"sssd-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"sssd-32bit-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"sssd-ad-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"sssd-ad-debuginfo-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"sssd-debuginfo-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"sssd-debuginfo-32bit-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"sssd-debugsource-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"sssd-ipa-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"sssd-ipa-debuginfo-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"sssd-krb5-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"sssd-krb5-common-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"sssd-krb5-common-debuginfo-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"sssd-krb5-debuginfo-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"sssd-ldap-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"sssd-ldap-debuginfo-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"sssd-proxy-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"sssd-proxy-debuginfo-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"sssd-tools-1.16.1-4.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"4", cpu:"x86_64", reference:"sssd-tools-debuginfo-1.16.1-4.3.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sssd");
}
