#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124929);
  script_version("1.5");
  script_cvs_date("Date: 2019/06/27 13:33:25");

  script_cve_id(
    "CVE-2017-15906",
    "CVE-2018-15473",
    "CVE-2018-20685",
    "CVE-2019-6109",
    "CVE-2019-6111"
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : openssh (EulerOS-SA-2019-1426)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the openssh packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - The process_open function in sftp-server.c in OpenSSH
    before 7.6 does not properly prevent write operations
    in readonly mode, which allows attackers to create
    zero-length files.(CVE-2017-15906)

  - In OpenSSH 7.9, scp.c in the scp client allows remote
    SSH servers to bypass intended access restrictions via
    the filename of . or an empty filename. The impact is
    modifying the permissions of the target directory on
    the client side.(CVE-2018-20685)

  - An issue was discovered in OpenSSH 7.9. Due to missing
    character encoding in the progress display, a malicious
    server (or Man-in-The-Middle attacker) can employ
    crafted object names to manipulate the client output,
    e.g., by using ANSI control codes to hide additional
    files being transferred. This affects
    refresh_progress_meter() in
    progressmeter.c.(CVE-2019-6109)

  - An issue was discovered in OpenSSH 7.9. Due to the scp
    implementation being derived from 1983 rcp, the server
    chooses which files/directories are sent to the client.
    However, the scp client only performs cursory
    validation of the object name returned (only directory
    traversal attacks are prevented). A malicious scp
    server (or Man-in-The-Middle attacker) can overwrite
    arbitrary files in the scp client target directory. If
    recursive operation (-r) is performed, the server can
    manipulate subdirectories as well (for example, to
    overwrite the .ssh/authorized_keys
    file).(CVE-2019-6111)

  - OpenSSH through 7.7 is prone to a user enumeration
    vulnerability due to not delaying bailout for an
    invalid authenticating user until after the packet
    containing the request has been fully parsed, related
    to auth2-gss.c, auth2-hostbased.c, and
    auth2-pubkey.c.(CVE-2018-15473)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1426
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected openssh packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssh-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssh-keycat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:pam_ssh_agent_auth");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["openssh-7.4p1-16.h8",
        "openssh-clients-7.4p1-16.h8",
        "openssh-keycat-7.4p1-16.h8",
        "openssh-server-7.4p1-16.h8",
        "pam_ssh_agent_auth-0.10.3-2.16"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
