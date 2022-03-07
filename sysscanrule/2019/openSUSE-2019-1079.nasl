#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1079.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(123542);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/02 21:54:17");

  script_cve_id("CVE-2018-16873", "CVE-2018-16874", "CVE-2018-16875", "CVE-2019-5736");

  script_name(english:"openSUSE Security Update : containerd / docker / docker-runc / etc (openSUSE-2019-1079)");
  script_summary(english:"Check for the openSUSE-2019-1079 patch");

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

Other changes and bug fixes :

  - Update shell completion to use Group: System/Shells.

  - Add daemon.json file with rotation logs configuration
    (bsc#1114832)

  - Update to Docker 18.09.1-ce (bsc#1124308) and to to runc
    96ec2177ae84. See upstream changelog in the packaged
    /usr/share/doc/packages/docker/CHANGELOG.md.

  - Disable leap based builds for kubic flavor
    (bsc#1121412).

  - Allow users to explicitly specify the NIS domain name of
    a container (bsc#1001161).

  - Update docker.service to match upstream and avoid rlimit
    problems (bsc#1112980).

  - Update go requirements to >= go1.10 

  - Use -buildmode=pie for tests and binary build
    (bsc#1048046 and bsc#1051429).

  - Remove the usage of 'cp -r' to reduce noise in the build
    logs.

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1001161"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112980"
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
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1121412"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd-kubic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd-kubic-ctr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd-kubic-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:containerd-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-kubic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-kubic-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-kubic-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-kubic-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-kubic-kubeadm-criconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-kubic-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-kubic-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-kubic-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-libnetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-libnetwork-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-libnetwork-kubic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-libnetwork-kubic-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-runc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-runc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-runc-kubic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-runc-kubic-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-runc-kubic-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-runc-kubic-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-runc-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:docker-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:golang-github-docker-libnetwork");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:golang-github-docker-libnetwork-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:golang-github-docker-libnetwork-kubic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:golang-github-docker-libnetwork-kubic-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/01");
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

if ( rpm_check(release:"SUSE42.3", reference:"containerd-1.2.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"containerd-ctr-1.2.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"containerd-kubic-1.2.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"containerd-kubic-ctr-1.2.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"containerd-kubic-test-1.2.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"containerd-test-1.2.2-22.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"docker-bash-completion-18.09.1_ce-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"docker-kubic-bash-completion-18.09.1_ce-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"docker-kubic-zsh-completion-18.09.1_ce-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"docker-libnetwork-0.7.0.1+gitr2711_2cfbf9b1f981-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"docker-libnetwork-debuginfo-0.7.0.1+gitr2711_2cfbf9b1f981-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"docker-libnetwork-kubic-0.7.0.1+gitr2711_2cfbf9b1f981-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"docker-libnetwork-kubic-debuginfo-0.7.0.1+gitr2711_2cfbf9b1f981-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"docker-runc-1.0.0rc6+gitr3748_96ec2177ae84-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"docker-runc-debuginfo-1.0.0rc6+gitr3748_96ec2177ae84-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"docker-runc-debugsource-1.0.0rc6+gitr3748_96ec2177ae84-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"docker-runc-kubic-1.0.0rc6+gitr3748_96ec2177ae84-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"docker-runc-kubic-debuginfo-1.0.0rc6+gitr3748_96ec2177ae84-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"docker-runc-kubic-debugsource-1.0.0rc6+gitr3748_96ec2177ae84-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"docker-runc-kubic-test-1.0.0rc6+gitr3748_96ec2177ae84-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"docker-runc-test-1.0.0rc6+gitr3748_96ec2177ae84-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"docker-zsh-completion-18.09.1_ce-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"golang-github-docker-libnetwork-0.7.0.1+gitr2711_2cfbf9b1f981-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"golang-github-docker-libnetwork-debugsource-0.7.0.1+gitr2711_2cfbf9b1f981-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"golang-github-docker-libnetwork-kubic-0.7.0.1+gitr2711_2cfbf9b1f981-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"golang-github-docker-libnetwork-kubic-debugsource-0.7.0.1+gitr2711_2cfbf9b1f981-11.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"docker-18.09.1_ce-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"docker-debuginfo-18.09.1_ce-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"docker-debugsource-18.09.1_ce-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"docker-kubic-18.09.1_ce-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"docker-kubic-debuginfo-18.09.1_ce-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"docker-kubic-debugsource-18.09.1_ce-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"docker-kubic-kubeadm-criconfig-18.09.1_ce-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"docker-kubic-test-18.09.1_ce-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"docker-kubic-test-debuginfo-18.09.1_ce-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"docker-test-18.09.1_ce-54.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"docker-test-debuginfo-18.09.1_ce-54.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "containerd / containerd-ctr / containerd-test / containerd-kubic / etc");
}
