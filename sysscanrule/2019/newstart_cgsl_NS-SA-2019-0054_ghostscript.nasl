#
# (C) WebRAY Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0054. The text
# itself is copyright (C) ZTE, Inc.

include("compat.inc");

if (description)
{
  script_id(127241);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:04:15");

  script_cve_id(
    "CVE-2018-16540",
    "CVE-2018-19475",
    "CVE-2018-19476",
    "CVE-2018-19477",
    "CVE-2019-6116"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : ghostscript Multiple Vulnerabilities (NS-SA-2019-0054)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has ghostscript packages installed that are
affected by multiple vulnerabilities:

  - It was discovered that the ghostscript PDF14 compositor
    did not properly handle the copying of a device. An
    attacker could possibly exploit this to bypass the
    -dSAFER protection and crash ghostscript or, possibly,
    execute arbitrary code in the ghostscript context via a
    specially crafted PostScript document. (CVE-2018-16540)

  - psi/zdevice2.c in Artifex Ghostscript before 9.26 allows
    remote attackers to bypass intended access restrictions
    because available stack space is not checked when the
    device remains the same. (CVE-2018-19475)

  - psi/zicc.c in Artifex Ghostscript before 9.26 allows
    remote attackers to bypass intended access restrictions
    because of a setcolorspace type confusion.
    (CVE-2018-19476)

  - psi/zfjbig2.c in Artifex Ghostscript before 9.26 allows
    remote attackers to bypass intended access restrictions
    because of a JBIG2Decode type confusion.
    (CVE-2018-19477)

  - It was found that ghostscript could leak sensitive
    operators on the operand stack when a pseudo-operator
    pushes a subroutine. A specially crafted PostScript file
    could use this flaw to escape the -dSAFER protection in
    order to, for example, have access to the file system
    outside of the SAFER constraints. (CVE-2019-6116)

Note that GizaNE has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0054");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL ghostscript packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6116");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/05");
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
    "ghostscript-9.07-31.el7_6.9",
    "ghostscript-cups-9.07-31.el7_6.9",
    "ghostscript-debuginfo-9.07-31.el7_6.9",
    "ghostscript-devel-9.07-31.el7_6.9",
    "ghostscript-doc-9.07-31.el7_6.9",
    "ghostscript-gtk-9.07-31.el7_6.9"
  ],
  "CGSL MAIN 5.04": [
    "ghostscript-9.07-31.el7_6.9",
    "ghostscript-cups-9.07-31.el7_6.9",
    "ghostscript-debuginfo-9.07-31.el7_6.9",
    "ghostscript-devel-9.07-31.el7_6.9",
    "ghostscript-doc-9.07-31.el7_6.9",
    "ghostscript-gtk-9.07-31.el7_6.9"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript");
}
