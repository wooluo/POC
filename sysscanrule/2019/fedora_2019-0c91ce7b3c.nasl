#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-0c91ce7b3c.
#

include("compat.inc");

if (description)
{
  script_id(124470);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/02 10:15:56");

  script_cve_id("CVE-2013-1752", "CVE-2018-14647", "CVE-2019-5010");
  script_xref(name:"FEDORA", value:"2019-0c91ce7b3c");

  script_name(english:"Fedora 30 : python2 / python2-docs (2019-0c91ce7b3c)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update legacy Python to 2.7.16. Most significant improvement is that
is builds against OpenSSL 1.1.1. See [upstream release
announcement](https://www.python.org/downloads/release/python-2716/)
and
[changelog](https://github.com/python/cpython/blob/2.7/Misc/NEWS.d/2.7
.16.rst) (+ [rc1
changelog](https://github.com/python/cpython/blob/2.7/Misc/NEWS.d/2.7.
16rc1.rst)).

Fixes the following CVEs :

  -
    [CVE-2019-5010](https://access.redhat.com/security/cve/c
    ve-2019-5010) Fix a NULL pointer deref in ssl module.
    The cert parser did not handle CRL distribution points
    with empty DP or URI correctly. A malicious or buggy
    certificate can result into segfault. Vulnerability
    (TALOS-2018-0758) reported by Colin Read and Nicolas
    Edet of Cisco.

  -
    [CVE-2013-1752](https://access.redhat.com/security/cve/c
    ve-2013-1752): Change use of readline() in
    `imaplib.IMAP4_SSL` to limit line length.

([CVE-2018-14647](https://access.redhat.com/security/cve/cve-2018-1464
7) is listed in upstream changelog, but it was already backported in
Fedora.)

Note that Python 2 is deprecated in Fedora 30 and users are advised to
switch to Python 3. Upstream support of Python 2 ends on 2020-01-01.

Note that WebRAY Network Security has extracted the preceding
description block directly from the Fedora update system website.
WebRAY has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2013-1752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2018-14647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/security/cve/cve-2019-5010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-0c91ce7b3c"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/python/cpython/blob/2.7/Misc/NEWS.d/2.7.16.rst"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.python.org/downloads/release/python-2716/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python2 and / or python2-docs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:python2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:python2-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:30");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^30([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 30", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC30", reference:"python2-2.7.16-1.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"python2-docs-2.7.16-1.fc30")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python2 / python2-docs");
}
