#
# (C) WebRAY Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0034. The text
# itself is copyright (C) ZTE, Inc.

include("compat.inc");

if (description)
{
  script_id(127203);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:04:15");

  script_cve_id(
    "CVE-2017-3636",
    "CVE-2017-3641",
    "CVE-2017-3651",
    "CVE-2017-3653",
    "CVE-2017-10268",
    "CVE-2017-10378",
    "CVE-2017-10379",
    "CVE-2017-10384",
    "CVE-2018-2562",
    "CVE-2018-2622",
    "CVE-2018-2640",
    "CVE-2018-2665",
    "CVE-2018-2668",
    "CVE-2018-2755",
    "CVE-2018-2761",
    "CVE-2018-2767",
    "CVE-2018-2771",
    "CVE-2018-2781",
    "CVE-2018-2813",
    "CVE-2018-2817",
    "CVE-2018-2819",
    "CVE-2018-3133",
    "CVE-2019-2455"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : mariadb Multiple Vulnerabilities (NS-SA-2019-0034)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has mariadb packages installed that are affected
by multiple vulnerabilities:

  - Vulnerability in the MySQL Server component of Oracle
    MySQL (subcomponent: Client mysqldump). Supported
    versions that are affected are 5.5.56 and earlier,
    5.6.36 and earlier and 5.7.18 and earlier. Easily
    exploitable vulnerability allows low privileged attacker
    with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized update, insert or delete
    access to some of MySQL Server accessible data. CVSS 3.0
    Base Score 4.3 (Integrity impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N).
    (CVE-2017-3651)

  - Vulnerability in the MySQL Server component of Oracle
    MySQL (subcomponent: Client programs). Supported
    versions that are affected are 5.5.56 and earlier and
    5.6.36 and earlier. Easily exploitable vulnerability
    allows low privileged attacker with logon to the
    infrastructure where MySQL Server executes to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized update, insert or delete
    access to some of MySQL Server accessible data as well
    as unauthorized read access to a subset of MySQL Server
    accessible data and unauthorized ability to cause a
    partial denial of service (partial DOS) of MySQL Server.
    CVSS 3.0 Base Score 5.3 (Confidentiality, Integrity and
    Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L).
    (CVE-2017-3636)

  - Vulnerability in the MySQL Server component of Oracle
    MySQL (subcomponent: Server: DML). Supported versions
    that are affected are 5.5.56 and earlier, 5.6.36 and
    earlier and 5.7.18 and earlier. Easily exploitable
    vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.0 Base Score 4.9 (Availability impacts).
    CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2017-3641)

  - Vulnerability in the MySQL Server component of Oracle
    MySQL (subcomponent: Server: DDL). Supported versions
    that are affected are 5.5.56 and earlier, 5.6.36 and
    earlier and 5.7.18 and earlier. Difficult to exploit
    vulnerability allows low privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized update, insert or delete
    access to some of MySQL Server accessible data. CVSS 3.0
    Base Score 3.1 (Integrity impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N).
    (CVE-2017-3653)

  - Vulnerability in the MySQL Server component of Oracle
    MySQL (subcomponent: Server: Optimizer). Supported
    versions that are affected are 5.5.57 and earlier,
    5.6.37 and earlier and 5.7.11 and earlier. Easily
    exploitable vulnerability allows low privileged attacker
    with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.0 Base Score 6.5 (Availability impacts).
    CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2017-10378)

  - Vulnerability in the MySQL Server component of Oracle
    MySQL (subcomponent: Server: Replication). Supported
    versions that are affected are 5.5.57 and earlier,
    5.6.37 and earlier and 5.7.19 and earlier. Difficult to
    exploit vulnerability allows high privileged attacker
    with logon to the infrastructure where MySQL Server
    executes to compromise MySQL Server. Successful attacks
    of this vulnerability can result in unauthorized access
    to critical data or complete access to all MySQL Server
    accessible data. CVSS 3.0 Base Score 4.1
    (Confidentiality impacts). CVSS Vector:
    (CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N).
    (CVE-2017-10268)

  - Vulnerability in the MySQL Server component of Oracle
    MySQL (subcomponent: Client programs). Supported
    versions that are affected are 5.5.57 and earlier,
    5.6.37 and earlier and 5.7.19 and earlier. Easily
    exploitable vulnerability allows low privileged attacker
    with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized access to critical data or
    complete access to all MySQL Server accessible data.
    CVSS 3.0 Base Score 6.5 (Confidentiality impacts). CVSS
    Vector: (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N).
    (CVE-2017-10379)

  - Vulnerability in the MySQL Server component of Oracle
    MySQL (subcomponent: Server: DDL). Supported versions
    that are affected are 5.5.57 and earlier 5.6.37 and
    earlier 5.7.19 and earlier. Easily exploitable
    vulnerability allows low privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.0 Base Score 6.5 (Availability impacts).
    CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2017-10384)

  - Vulnerability in the MySQL Server component of Oracle
    MySQL (subcomponent: Server: Replication). Supported
    versions that are affected are 5.5.59 and prior, 5.6.39
    and prior and 5.7.21 and prior. Difficult to exploit
    vulnerability allows unauthenticated attacker with logon
    to the infrastructure where MySQL Server executes to
    compromise MySQL Server. Successful attacks require
    human interaction from a person other than the attacker
    and while the vulnerability is in MySQL Server, attacks
    may significantly impact additional products. Successful
    attacks of this vulnerability can result in takeover of
    MySQL Server. CVSS 3.0 Base Score 7.7 (Confidentiality,
    Integrity and Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H).
    (CVE-2018-2755)

  - Vulnerability in the MySQL Server component of Oracle
    MySQL (subcomponent: Server: Security: Encryption).
    Supported versions that are affected are 5.5.60 and
    prior, 5.6.40 and prior and 5.7.22 and prior. Difficult
    to exploit vulnerability allows low privileged attacker
    with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized read access to a subset of
    MySQL Server accessible data. CVSS 3.0 Base Score 3.1
    (Confidentiality impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N).
    (CVE-2018-2767)

  - Vulnerability in the MySQL Server component of Oracle
    MySQL (subcomponent: Server : Partition). Supported
    versions that are affected are 5.5.58 and prior, 5.6.38
    and prior and 5.7.19 and prior. Easily exploitable
    vulnerability allows low privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server as well as unauthorized update, insert or delete
    access to some of MySQL Server accessible data. CVSS 3.0
    Base Score 7.1 (Integrity and Availability impacts).
    CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H).
    (CVE-2018-2562)

  - Vulnerability in the MySQL Server component of Oracle
    MySQL (subcomponent: Server: DDL). Supported versions
    that are affected are 5.5.58 and prior, 5.6.38 and prior
    and 5.7.20 and prior. Easily exploitable vulnerability
    allows low privileged attacker with network access via
    multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server. CVSS
    3.0 Base Score 6.5 (Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2018-2622)

  - Vulnerability in the MySQL Server component of Oracle
    MySQL (subcomponent: Server: Optimizer). Supported
    versions that are affected are 5.5.58 and prior, 5.6.38
    and prior and 5.7.20 and prior. Easily exploitable
    vulnerability allows low privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.0 Base Score 6.5 (Availability impacts).
    CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2018-2640, CVE-2018-2665, CVE-2018-2668)

  - Vulnerability in the MySQL Server component of Oracle
    MySQL (subcomponent: Client programs). Supported
    versions that are affected are 5.5.59 and prior, 5.6.39
    and prior and 5.7.21 and prior. Difficult to exploit
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.0 Base Score 5.9 (Availability impacts).
    CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2018-2761)

  - Vulnerability in the MySQL Server component of Oracle
    MySQL (subcomponent: Server: Locking). Supported
    versions that are affected are 5.5.59 and prior, 5.6.39
    and prior and 5.7.21 and prior. Difficult to exploit
    vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.0 Base Score 4.4 (Availability impacts).
    CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2018-2771)

  - Vulnerability in the MySQL Server component of Oracle
    MySQL (subcomponent: Server: Optimizer). Supported
    versions that are affected are 5.5.59 and prior, 5.6.39
    and prior and 5.7.21 and prior. Easily exploitable
    vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.0 Base Score 4.9 (Availability impacts).
    CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2018-2781)

  - Vulnerability in the MySQL Server component of Oracle
    MySQL (subcomponent: Server: DDL). Supported versions
    that are affected are 5.5.59 and prior, 5.6.39 and prior
    and 5.7.21 and prior. Easily exploitable vulnerability
    allows low privileged attacker with network access via
    multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in
    unauthorized read access to a subset of MySQL Server
    accessible data. CVSS 3.0 Base Score 4.3
    (Confidentiality impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N).
    (CVE-2018-2813)

  - Vulnerability in the MySQL Server component of Oracle
    MySQL (subcomponent: Server: DDL). Supported versions
    that are affected are 5.5.59 and prior, 5.6.39 and prior
    and 5.7.21 and prior. Easily exploitable vulnerability
    allows low privileged attacker with network access via
    multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server. CVSS
    3.0 Base Score 6.5 (Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2018-2817)

  - Vulnerability in the MySQL Server component of Oracle
    MySQL (subcomponent: InnoDB). Supported versions that
    are affected are 5.5.59 and prior, 5.6.39 and prior and
    5.7.21 and prior. Easily exploitable vulnerability
    allows low privileged attacker with network access via
    multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server. CVSS
    3.0 Base Score 6.5 (Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2018-2819)

  - Vulnerability in the MySQL Server component of Oracle
    MySQL (subcomponent: Server: Parser). Supported versions
    that are affected are 5.6.42 and prior, 5.7.24 and prior
    and 8.0.13 and prior. Easily exploitable vulnerability
    allows low privileged attacker with network access via
    multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server. CVSS
    3.0 Base Score 6.5 (Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2019-2455)

  - Vulnerability in the MySQL Server component of Oracle
    MySQL (subcomponent: Server: Parser). Supported versions
    that are affected are 5.5.61 and prior, 5.6.41 and
    prior, 5.7.23 and prior and 8.0.12 and prior. Easily
    exploitable vulnerability allows low privileged attacker
    with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability
    can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL
    Server. CVSS 3.0 Base Score 6.5 (Availability impacts).
    CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2018-3133)

Note that GizaNE has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0034");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL mariadb packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2562");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/08");
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
    "mariadb-5.5.60-1.el7_5",
    "mariadb-bench-5.5.60-1.el7_5",
    "mariadb-debuginfo-5.5.60-1.el7_5",
    "mariadb-devel-5.5.60-1.el7_5",
    "mariadb-embedded-5.5.60-1.el7_5",
    "mariadb-embedded-devel-5.5.60-1.el7_5",
    "mariadb-libs-5.5.60-1.el7_5",
    "mariadb-server-5.5.60-1.el7_5",
    "mariadb-test-5.5.60-1.el7_5"
  ],
  "CGSL MAIN 5.04": [
    "mariadb-5.5.60-1.el7_5",
    "mariadb-bench-5.5.60-1.el7_5",
    "mariadb-debuginfo-5.5.60-1.el7_5",
    "mariadb-devel-5.5.60-1.el7_5",
    "mariadb-embedded-5.5.60-1.el7_5",
    "mariadb-embedded-devel-5.5.60-1.el7_5",
    "mariadb-libs-5.5.60-1.el7_5",
    "mariadb-server-5.5.60-1.el7_5",
    "mariadb-test-5.5.60-1.el7_5"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mariadb");
}
