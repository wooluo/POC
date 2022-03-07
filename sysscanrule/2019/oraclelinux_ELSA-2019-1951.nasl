#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:1951 and 
# Oracle Linux Security Advisory ELSA-2019-1951 respectively.
#

include("compat.inc");

if (description)
{
  script_id(127609);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2018-18508", "CVE-2019-11719", "CVE-2019-11727", "CVE-2019-11729");
  script_xref(name:"RHSA", value:"2019:1951");

  script_name(english:"Oracle Linux 8 : nspr / nss (ELSA-2019-1951)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2019:1951 :

An update for nss and nspr is now available for Red Hat Enterprise
Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications.

Netscape Portable Runtime (NSPR) provides platform independence for
non-GUI operating system facilities.

The following packages have been upgraded to a later upstream version:
nss (3.44.0), nspr (4.21.0). (BZ#1713187, BZ#1713188)

Security Fix(es) :

* nss: NULL pointer dereference in several CMS functions resulting in
a denial of service (CVE-2018-18508)

* nss: Out-of-bounds read when importing curve25519 private key
(CVE-2019-11719)

* nss: Empty or malformed p256-ECDH public keys may trigger a
segmentation fault (CVE-2019-11729)

* nss: PKCS#1 v1.5 signatures can be used for TLS 1.3 (CVE-2019-11727)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section.

Bug Fix(es) :

* PQG verify fails when create DSA PQG parameters because the counts
aren't returned correctly. (BZ#1685325)

* zeroization of AES context missing (BZ#1719629)

* RSA Pairwise consistency test (BZ#1719630)

* FIPS updated for nss-softoken POST (BZ#1722373)

* DH/ECDH key tests missing for the PG parameters (BZ#1722374)

* NSS should implement continuous random test on it's seed data or use
the kernel AF_ALG interface for random (BZ#1725059)

* support setting supported signature algorithms in strsclnt utility
(BZ# 1725110)

* certutil -F with no parameters is killed with segmentation fault
message (BZ#1725115)

* NSS: Support for IKE/IPsec typical PKIX usage so libreswan can use
nss without rejecting certs based on EKU (BZ#1725116)

* NSS should use getentropy() for seeding its RNG, not /dev/urandom.
Needs update to NSS 3.37 (BZ#1725117)

* Disable TLS 1.3 in FIPS mode (BZ#1725773)

* Wrong alert sent when client uses PKCS#1 signatures in TLS 1.3
(BZ#1728259)

* x25519 allowed in FIPS mode (BZ#1728260)

* post handshake authentication with selfserv does not work if
SSL_ENABLE_SESSION_TICKETS is set (BZ#1728261)

Enhancement(s) :

* Move IKEv1 and IKEv2 KDF's from libreswan to nss-softkn (BZ#1719628)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2019-August/009011.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nspr and / or nss packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-softokn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-softokn-freebl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-softokn-freebl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 8", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nspr-4.21.0-2.el8_0")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nspr-devel-4.21.0-2.el8_0")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nss-3.44.0-7.el8_0")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nss-devel-3.44.0-7.el8_0")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nss-softokn-3.44.0-7.el8_0")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nss-softokn-devel-3.44.0-7.el8_0")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nss-softokn-freebl-3.44.0-7.el8_0")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nss-softokn-freebl-devel-3.44.0-7.el8_0")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nss-sysinit-3.44.0-7.el8_0")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nss-tools-3.44.0-7.el8_0")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nss-util-3.44.0-7.el8_0")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"nss-util-devel-3.44.0-7.el8_0")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nspr / nspr-devel / nss / nss-devel / nss-softokn / etc");
}
