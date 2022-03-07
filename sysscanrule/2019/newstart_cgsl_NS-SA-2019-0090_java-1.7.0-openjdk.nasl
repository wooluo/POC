#
# (C) WebRAY Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0090. The text
# itself is copyright (C) ZTE, Inc.

include("compat.inc");

if (description)
{
  script_id(127309);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:04:15");

  script_cve_id(
    "CVE-2019-2422",
    "CVE-2019-2602",
    "CVE-2019-2684",
    "CVE-2019-2698"
  );

  script_name(english:"NewStart CGSL MAIN 4.06 : java-1.7.0-openjdk Multiple Vulnerabilities (NS-SA-2019-0090)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.06, has java-1.7.0-openjdk packages installed that are affected by
multiple vulnerabilities:

  - Vulnerability in the Java SE component of Oracle Java SE
    (subcomponent: Libraries). Supported versions that are
    affected are Java SE: 7u201, 8u192 and 11.0.1; Java SE
    Embedded: 8u191. Difficult to exploit vulnerability
    allows unauthenticated attacker with network access via
    multiple protocols to compromise Java SE. Successful
    attacks require human interaction from a person other
    than the attacker. Successful attacks of this
    vulnerability can result in unauthorized read access to
    a subset of Java SE accessible data. Note: This
    vulnerability applies to Java deployments, typically in
    clients running sandboxed Java Web Start applications or
    sandboxed Java applets (in Java SE 8), that load and run
    untrusted code (e.g., code that comes from the internet)
    and rely on the Java sandbox for security. This
    vulnerability does not apply to Java deployments,
    typically in servers, that load and run only trusted
    code (e.g., code installed by an administrator). CVSS
    3.0 Base Score 3.1 (Confidentiality impacts). CVSS
    Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N).
    (CVE-2019-2422)

  - Vulnerability in the Java SE, Java SE Embedded component
    of Oracle Java SE (subcomponent: Libraries). Supported
    versions that are affected are Java SE: 7u211, 8u202,
    11.0.2 and 12; Java SE Embedded: 8u201. Easily
    exploitable vulnerability allows unauthenticated
    attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks
    of this vulnerability can result in unauthorized ability
    to cause a hang or frequently repeatable crash (complete
    DOS) of Java SE, Java SE Embedded. Note: This
    vulnerability can only be exploited by supplying data to
    APIs in the specified Component without using Untrusted
    Java Web Start applications or Untrusted Java applets,
    such as through a web service. CVSS 3.0 Base Score 7.5
    (Availability impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2019-2602)

  - Vulnerability in the Java SE component of Oracle Java SE
    (subcomponent: 2D). Supported versions that are affected
    are Java SE: 7u211 and 8u202. Difficult to exploit
    vulnerability allows unauthenticated attacker with
    network access via multiple protocols to compromise Java
    SE. Successful attacks of this vulnerability can result
    in takeover of Java SE. Note: This vulnerability applies
    to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java
    applets (in Java SE 8), that load and run untrusted code
    (e.g., code that comes from the internet) and rely on
    the Java sandbox for security. This vulnerability does
    not apply to Java deployments, typically in servers,
    that load and run only trusted code (e.g., code
    installed by an administrator). CVSS 3.0 Base Score 8.1
    (Confidentiality, Integrity and Availability impacts).
    CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H).
    (CVE-2019-2698)

  - Vulnerability in the Java SE, Java SE Embedded component
    of Oracle Java SE (subcomponent: RMI). Supported
    versions that are affected are Java SE: 7u211, 8u202,
    11.0.2 and 12; Java SE Embedded: 8u201. Difficult to
    exploit vulnerability allows unauthenticated attacker
    with network access via multiple protocols to compromise
    Java SE, Java SE Embedded. Successful attacks of this
    vulnerability can result in unauthorized creation,
    deletion or modification access to critical data or all
    Java SE, Java SE Embedded accessible data. Note: This
    vulnerability applies to Java deployments, typically in
    clients running sandboxed Java Web Start applications or
    sandboxed Java applets (in Java SE 8), that load and run
    untrusted code (e.g., code that comes from the internet)
    and rely on the Java sandbox for security. This
    vulnerability can also be exploited by using APIs in the
    specified Component, e.g., through a web service which
    supplies data to the APIs. CVSS 3.0 Base Score 5.9
    (Integrity impacts). CVSS Vector:
    (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N).
    (CVE-2019-2684)

Note that GizaNE has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0090");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL java-1.7.0-openjdk packages. Note that updated packages may not be available yet. Please
contact ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2698");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
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

if (release !~ "CGSL MAIN 4.06")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.06');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.06": [
    "java-1.7.0-openjdk-1.7.0.221-2.6.18.0.el6_10",
    "java-1.7.0-openjdk-debuginfo-1.7.0.221-2.6.18.0.el6_10",
    "java-1.7.0-openjdk-demo-1.7.0.221-2.6.18.0.el6_10",
    "java-1.7.0-openjdk-devel-1.7.0.221-2.6.18.0.el6_10",
    "java-1.7.0-openjdk-javadoc-1.7.0.221-2.6.18.0.el6_10",
    "java-1.7.0-openjdk-src-1.7.0.221-2.6.18.0.el6_10"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-openjdk");
}
