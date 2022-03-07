#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125005);
  script_version("1.4");
  script_cvs_date("Date: 2019/06/27 13:33:26");

  script_cve_id(
    "CVE-2012-4412",
    "CVE-2013-1914",
    "CVE-2013-4237",
    "CVE-2013-4788",
    "CVE-2013-7423",
    "CVE-2014-0475",
    "CVE-2014-6040",
    "CVE-2014-9402",
    "CVE-2014-9761",
    "CVE-2015-1472",
    "CVE-2015-1781",
    "CVE-2015-5277",
    "CVE-2015-8776",
    "CVE-2016-3075",
    "CVE-2017-15670",
    "CVE-2019-9169"
  );
  script_bugtraq_id(
    55462,
    58839,
    61183,
    61729,
    68505,
    69472,
    71670,
    72428,
    72498,
    72844,
    74255
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : glibc (EulerOS-SA-2019-1552)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the glibc packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - It was discovered that the nss_files backend for the
    Name Service Switch in glibc would return incorrect
    data to applications or corrupt the heap (depending on
    adjacent heap contents). A local attacker could
    potentially use this flaw to execute arbitrary code on
    the system.(CVE-2015-5277)

  - A directory traveral flaw was found in the way glibc
    loaded locale files. An attacker able to make an
    application use a specially crafted locale name value
    (for example, specified in an LC_* environment
    variable) could possibly use this flaw to execute
    arbitrary code with the privileges of that
    application.(CVE-2014-0475)

  - It was found that out-of-range time values passed to
    the strftime() function could result in an
    out-of-bounds memory access. This could lead to
    application crash or, potentially, information
    disclosure.(CVE-2015-8776)

  - The GNU C Library (aka glibc or libc6) before 2.27
    contains an off-by-one error leading to a heap-based
    buffer overflow in the glob function in glob.c, related
    to the processing of home directories using the ~
    operator followed by a long string.(CVE-2017-15670)

  - The PTR_MANGLE implementation in the GNU C Library (aka
    glibc or libc6) 2.4, 2.17, and earlier, and Embedded
    GLIBC (EGLIBC) does not initialize the random value for
    the pointer guard, which makes it easier for
    context-dependent attackers to control execution flow
    by leveraging a buffer-overflow vulnerability in an
    application and using the known zero value pointer
    guard to calculate a pointer address.(CVE-2013-4788)

  - An out-of-bounds read flaw was found in the way glibc's
    iconv() function converted certain encoded data to
    UTF-8. An attacker able to make an application call the
    iconv() function with a specially crafted argument
    could use this flaw to crash that
    application.(CVE-2014-6040)

  - A stack overflow vulnerability was found in
    _nss_dns_getnetbyname_r. On systems with nsswitch
    configured to include ''networks: dns'' with a
    privileged or network-facing service that would attempt
    to resolve user-provided network names, an attacker
    could provide an excessively long network name,
    resulting in stack corruption and code
    execution.(CVE-2016-3075)

  - Integer overflow in string/strcoll_l.c in the GNU C
    Library (aka glibc or libc6) 2.17 and earlier allows
    context-dependent attackers to cause a denial of
    service (crash) or possibly execute arbitrary code via
    a long string, which triggers a heap-based buffer
    overflow.(CVE-2012-4412)

  - A heap-based buffer overflow flaw was found in glibc's
    swscanf() function. An attacker able to make an
    application call the swscanf() function could use this
    flaw to crash that application or, potentially, execute
    arbitrary code with the permissions of the user running
    the application.(CVE-2015-1472)

  - It was found that getaddrinfo() did not limit the
    amount of stack memory used during name resolution. An
    attacker able to make an application resolve an
    attacker-controlled hostname or IP address could
    possibly cause the application to exhaust all stack
    memory and crash.(CVE-2013-1914)

  - A stack overflow vulnerability was found in nan*
    functions that could cause applications, which process
    long strings with the nan function, to crash or,
    potentially, execute arbitrary code.(CVE-2014-9761)

  - An out-of-bounds write flaw was found in the way the
    glibc's readdir_r() function handled file system
    entries longer than the NAME_MAX character constant. A
    remote attacker could provide a specially crafted NTFS
    or CIFS file system that, when processed by an
    application using readdir_r(), would cause that
    application to crash or, potentially, allow the
    attacker to execute arbitrary code with the privileges
    of the user running the application.(CVE-2013-4237)

  - It was discovered that, under certain circumstances,
    glibc's getaddrinfo() function would send DNS queries
    to random file descriptors. An attacker could
    potentially use this flaw to send DNS queries to
    unintended recipients, resulting in information
    disclosure or data loss due to the application
    encountering corrupted data.(CVE-2013-7423)

  - A buffer overflow flaw was found in the way glibc's
    gethostbyname_r() and other related functions computed
    the size of a buffer when passed a misaligned buffer as
    input. An attacker able to make an application call any
    of these functions with a misaligned buffer could use
    this flaw to crash the application or, potentially,
    execute arbitrary code with the permissions of the user
    running the application.(CVE-2015-1781)

  - The nss_dns implementation of getnetbyname in GNU C
    Library (aka glibc) before 2.21, when the DNS backend
    in the Name Service Switch configuration is enabled,
    allows remote attackers to cause a denial of service
    (infinite loop) by sending a positive answer while a
    network name is being process.(CVE-2014-9402)

  - In the GNU C Library (aka glibc or libc6) through 2.29,
    proceed_next_node in posix/regexec.c has a heap-based
    buffer over-read via an attempted case-insensitive
    regular-expression match.(CVE-2019-9169)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1552
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected glibc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nscd");
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

pkgs = ["glibc-2.17-222.h11",
        "glibc-common-2.17-222.h11",
        "glibc-devel-2.17-222.h11",
        "glibc-headers-2.17-222.h11",
        "nscd-2.17-222.h11"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc");
}
