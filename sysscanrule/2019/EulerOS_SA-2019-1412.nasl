#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124915);
  script_version("1.6");
  script_cvs_date("Date: 2019/07/02 12:46:54");

  script_cve_id(
    "CVE-2018-1049",
    "CVE-2018-15688",
    "CVE-2018-16864",
    "CVE-2018-16865",
    "CVE-2019-6454"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : systemd (EulerOS-SA-2019-1412)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the systemd packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - An allocation of memory without limits, that could
    result in the stack clashing with another memory
    region, was discovered in systemd-journald when a
    program with long command line arguments calls syslog.
    A local attacker may use this flaw to crash
    systemd-journald or escalate his privileges. Versions
    through v240 are vulnerable.(CVE-2018-16864)

  - An allocation of memory without limits, that could
    result in the stack clashing with another memory
    region, was discovered in systemd-journald when many
    entries are sent to the journal socket. A local
    attacker, or a remote one if systemd-journal-remote is
    used, may use this flaw to crash systemd-journald or
    execute code with journald privileges. Versions through
    v240 are vulnerable.(CVE-2018-16865)

  - An issue was discovered in sd-bus in systemd 239.
    bus_process_object() in libsystemd/sd-bus/bus-objects.c
    allocates a variable-length stack buffer for
    temporarily storing the object path of incoming D-Bus
    messages. An unprivileged local user can exploit this
    by sending a specially crafted message to PID1, causing
    the stack pointer to jump over the stack guard pages
    into an unmapped memory region and trigger a denial of
    service (systemd PID1 crash and kernel
    panic).(CVE-2019-6454)

  - A race condition was found in systemd. This could
    result in automount requests not being serviced and
    processes using them could hang, causing denial of
    service.(CVE-2018-1049)

  - It was discovered that systemd-network does not
    correctly keep track of a buffer size when constructing
    DHCPv6 packets. This flaw may lead to an integer
    underflow that can be used to produce an heap-based
    buffer overflow. A malicious host on the same network
    segment as the victim's one may advertise itself as a
    DHCPv6 server and exploit this flaw to cause a Denial
    of Service or potentially gain code execution on the
    victim's machine.(CVE-2018-15688)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1412
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected systemd packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libgudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:systemd-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:systemd-networkd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:systemd-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:systemd-resolved");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:systemd-sysv");
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
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["libgudev1-219-57.h82",
        "systemd-219-57.h82",
        "systemd-libs-219-57.h82",
        "systemd-networkd-219-57.h82",
        "systemd-python-219-57.h82",
        "systemd-resolved-219-57.h82",
        "systemd-sysv-219-57.h82"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "systemd");
}
