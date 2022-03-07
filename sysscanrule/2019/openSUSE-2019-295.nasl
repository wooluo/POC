#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-295.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(122660);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/02 21:54:17");

  script_cve_id("CVE-2018-16873", "CVE-2018-16874", "CVE-2018-16875", "CVE-2019-5736");

  script_name(english:"openSUSE Security Update : containerd / docker / docker-runc / etc (openSUSE-2019-295)");
  script_summary(english:"Check for the openSUSE-2019-295 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for containerd, docker, docker-runc,
golang-github-docker-libnetwork, runc fixes the following issues :

Security issues fixed :

  - CVE-2018-16875: Fixed a CPU Denial of Service
    (bsc#1118899).

  - CVE-2018-16874: Fixed a vulnerabity in go get command
    which could allow directory traversal in GOPATH mode
    (bsc#1118898).

  - CVE-2018-16873: Fixed a vulnerability in go get command
    which could allow remote code execution when executed
    with -u in GOPATH mode (bsc#1118897).

  - CVE-2019-5736: Effectively copying /proc/self/exe during
    re-exec to avoid write attacks to the host runc binary,
    which could lead to a container breakout (bsc#1121967).

Other changes and fixes :

  - Update shell completion to use Group: System/Shells.

  - Add daemon.json file with rotation logs configuration
    (bsc#1114832)

  - Update to Docker 18.09.1-ce (bsc#1124308) and to to runc
    96ec2177ae84. See upstream changelog in the packaged
    /usr/share/doc/packages/docker/CHANGELOG.md.

  - Update go requirements to >= go1.10 

  - Use -buildmode=pie for tests and binary build
    (bsc#1048046 and bsc#1051429).

  - Remove the usage of 'cp -r' to reduce noise in the build
    logs.

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048046"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121967"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1124308"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected containerd / docker / docker-runc / etc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd-ctr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-libnetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-libnetwork-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-runc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-runc-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:golang-github-docker-libnetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:runc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:runc-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/07");
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

if ( rpm_check(release:"SUSE15.0", reference:"containerd-1.2.2-lp150.4.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"containerd-ctr-1.2.2-lp150.4.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"containerd-test-1.2.2-lp150.4.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-18.09.1_ce-lp150.5.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-bash-completion-18.09.1_ce-lp150.5.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-debuginfo-18.09.1_ce-lp150.5.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-debugsource-18.09.1_ce-lp150.5.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-libnetwork-0.7.0.1+gitr2711_2cfbf9b1f981-lp150.3.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-libnetwork-debuginfo-0.7.0.1+gitr2711_2cfbf9b1f981-lp150.3.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-runc-1.0.0rc6+gitr3748_96ec2177ae84-lp150.5.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-runc-debuginfo-1.0.0rc6+gitr3748_96ec2177ae84-lp150.5.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-runc-test-1.0.0rc6+gitr3748_96ec2177ae84-lp150.5.14.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-test-18.09.1_ce-lp150.5.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-test-debuginfo-18.09.1_ce-lp150.5.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"docker-zsh-completion-18.09.1_ce-lp150.5.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"golang-github-docker-libnetwork-0.7.0.1+gitr2711_2cfbf9b1f981-lp150.3.10.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"runc-1.0.0~rc6-lp150.2.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"runc-debuginfo-1.0.0~rc6-lp150.2.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"runc-test-1.0.0~rc6-lp150.2.7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "containerd / containerd-ctr / containerd-test / docker-runc / etc");
}
