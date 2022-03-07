#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1228.
#

include("compat.inc");

if (description)
{
  script_id(125900);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/10 16:04:12");

  script_cve_id("CVE-2019-2602", "CVE-2019-2684", "CVE-2019-2697", "CVE-2019-2698");
  script_xref(name:"ALAS", value:"2019-1228");

  script_name(english:"Amazon Linux 2 : java-11-amazon-corretto (ALAS-2019-1228)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Vulnerability in the Java SE component of Oracle Java SE
(subcomponent: 2D). Supported versions that are affected are Java SE:
7u211 and 8u202. Difficult to exploit vulnerability allows
unauthenticated attacker with network access via multiple protocols to
compromise Java SE. Successful attacks of this vulnerability can
result in takeover of Java SE. Note: This vulnerability applies to
Java deployments, typically in clients running sandboxed Java Web
Start applications or sandboxed Java applets (in Java SE 8), that load
and run untrusted code (e.g., code that comes from the internet) and
rely on the Java sandbox for security. This vulnerability does not
apply to Java deployments, typically in servers, that load and run
only trusted code (e.g., code installed by an administrator). CVSS 3.0
Base Score 8.1 (Confidentiality, Integrity and Availability impacts).
CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H).
(CVE-2019-2697)

Vulnerability in the Java SE component of Oracle Java SE
(subcomponent: 2D). Supported versions that are affected are Java SE:
7u211 and 8u202. Difficult to exploit vulnerability allows
unauthenticated attacker with network access via multiple protocols to
compromise Java SE. Successful attacks of this vulnerability can
result in takeover of Java SE. Note: This vulnerability applies to
Java deployments, typically in clients running sandboxed Java Web
Start applications or sandboxed Java applets (in Java SE 8), that load
and run untrusted code (e.g., code that comes from the internet) and
rely on the Java sandbox for security. This vulnerability does not
apply to Java deployments, typically in servers, that load and run
only trusted code (e.g., code installed by an administrator). CVSS 3.0
Base Score 8.1 (Confidentiality, Integrity and Availability impacts).
CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H).
(CVE-2019-2698)

Vulnerability in the Java SE, Java SE Embedded component of Oracle
Java SE (subcomponent: Libraries). Supported versions that are
affected are Java SE: 7u211, 8u202, 11.0.2 and 12; Java SE Embedded:
8u201. Easily exploitable vulnerability allows unauthenticated
attacker with network access via multiple protocols to compromise Java
SE, Java SE Embedded. Successful attacks of this vulnerability can
result in unauthorized ability to cause a hang or frequently
repeatable crash (complete DOS) of Java SE, Java SE Embedded. Note:
This vulnerability can only be exploited by supplying data to APIs in
the specified Component without using Untrusted Java Web Start
applications or Untrusted Java applets, such as through a web service.
CVSS 3.0 Base Score 7.5 (Availability impacts). CVSS Vector:
(CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H). (CVE-2019-2602)

Vulnerability in the Java SE, Java SE Embedded component of Oracle
Java SE (subcomponent: RMI). Supported versions that are affected are
Java SE: 7u211, 8u202, 11.0.2 and 12; Java SE Embedded: 8u201.
Difficult to exploit vulnerability allows unauthenticated attacker
with network access via multiple protocols to compromise Java SE, Java
SE Embedded. Successful attacks of this vulnerability can result in
unauthorized creation, deletion or modification access to critical
data or all Java SE, Java SE Embedded accessible data. Note: This
vulnerability applies to Java deployments, typically in clients
running sandboxed Java Web Start applications or sandboxed Java
applets (in Java SE 8), that load and run untrusted code (e.g., code
that comes from the internet) and rely on the Java sandbox for
security. This vulnerability can also be exploited by using APIs in
the specified Component, e.g., through a web service which supplies
data to the APIs. CVSS 3.0 Base Score 5.9 (Integrity impacts). CVSS
Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N).
(CVE-2019-2684)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1228.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update java-11-amazon-corretto' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-11-amazon-corretto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-11-amazon-corretto-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:java-11-amazon-corretto-javadoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"java-11-amazon-corretto-11.0.3+7-1.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"java-11-amazon-corretto-headless-11.0.3+7-1.amzn2")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"java-11-amazon-corretto-javadoc-11.0.3+7-1.amzn2")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-11-amazon-corretto / java-11-amazon-corretto-headless / etc");
}
