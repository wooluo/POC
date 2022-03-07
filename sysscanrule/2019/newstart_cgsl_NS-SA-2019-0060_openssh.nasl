#
# (C) WebRAY Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0060. The text
# itself is copyright (C) ZTE, Inc.

include("compat.inc");

if (description)
{
  script_id(127253);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:04:15");

  script_cve_id(
    "CVE-2018-20685",
    "CVE-2019-6109",
    "CVE-2019-6110",
    "CVE-2019-6111"
  );
  script_bugtraq_id(106531);

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : openssh Multiple Vulnerabilities (NS-SA-2019-0060)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has openssh packages installed that are affected
by multiple vulnerabilities:

  - In OpenSSH 7.9, scp.c in the scp client allows remote
    SSH servers to bypass intended access restrictions via
    the filename of . or an empty filename. The impact is
    modifying the permissions of the target directory on the
    client side. (CVE-2018-20685)

  - An issue was discovered in OpenSSH 7.9. Due to missing
    character encoding in the progress display, a malicious
    server (or Man-in-The-Middle attacker) can employ
    crafted object names to manipulate the client output,
    e.g., by using ANSI control codes to hide additional
    files being transferred. This affects
    refresh_progress_meter() in progressmeter.c.
    (CVE-2019-6109)

  - In OpenSSH 7.9, due to accepting and displaying
    arbitrary stderr output from the server, a malicious
    server (or Man-in-The-Middle attacker) can manipulate
    the client output, for example to use ANSI control codes
    to hide additional files being transferred.
    (CVE-2019-6110)

  - An issue was discovered in OpenSSH 7.9. Due to the scp
    implementation being derived from 1983 rcp, the server
    chooses which files/directories are sent to the client.
    However, the scp client only performs cursory validation
    of the object name returned (only directory traversal
    attacks are prevented). A malicious scp server (or Man-
    in-The-Middle attacker) can overwrite arbitrary files in
    the scp client target directory. If recursive operation
    (-r) is performed, the server can manipulate
    subdirectories as well (for example, to overwrite the
    .ssh/authorized_keys file). (CVE-2019-6111)

Note that GizaNE has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0060");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL openssh packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6111");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.04": [
    "openssh-7.9p1-1.el7.cgslv5.0.7.ga049176",
    "openssh-askpass-7.9p1-1.el7.cgslv5.0.7.ga049176",
    "openssh-cavs-7.9p1-1.el7.cgslv5.0.7.ga049176",
    "openssh-clients-7.9p1-1.el7.cgslv5.0.7.ga049176",
    "openssh-debuginfo-7.9p1-1.el7.cgslv5.0.7.ga049176",
    "openssh-keycat-7.9p1-1.el7.cgslv5.0.7.ga049176",
    "openssh-ldap-7.9p1-1.el7.cgslv5.0.7.ga049176",
    "openssh-server-7.9p1-1.el7.cgslv5.0.7.ga049176",
    "pam_ssh_agent_auth-0.10.3-6.1.el7.cgslv5.0.7.ga049176"
  ],
  "CGSL MAIN 5.04": [
    "openssh-7.9p1-1.el7.cgslv5.0.7.ga049176",
    "openssh-askpass-7.9p1-1.el7.cgslv5.0.7.ga049176",
    "openssh-cavs-7.9p1-1.el7.cgslv5.0.7.ga049176",
    "openssh-clients-7.9p1-1.el7.cgslv5.0.7.ga049176",
    "openssh-debuginfo-7.9p1-1.el7.cgslv5.0.7.ga049176",
    "openssh-keycat-7.9p1-1.el7.cgslv5.0.7.ga049176",
    "openssh-ldap-7.9p1-1.el7.cgslv5.0.7.ga049176",
    "openssh-server-7.9p1-1.el7.cgslv5.0.7.ga049176",
    "pam_ssh_agent_auth-0.10.3-6.1.el7.cgslv5.0.7.ga049176"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh");
}
