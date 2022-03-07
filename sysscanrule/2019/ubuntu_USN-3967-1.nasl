#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-3967-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124678);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/07 11:27:39");

  script_cve_id("CVE-2018-15822", "CVE-2019-11338", "CVE-2019-11339", "CVE-2019-9718", "CVE-2019-9721");
  script_xref(name:"USN", value:"3967-1");

  script_name(english:"Ubuntu 18.04 LTS / 18.10 / 19.04 : FFmpeg vulnerabilities (USN-3967-1)");
  script_summary(english:"Checks dpkg output for updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Ubuntu host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that FFmpeg contained multiple security issues when
handling certain multimedia files. If a user were tricked into opening
a crafted multimedia file, an attacker could cause a denial of service
via application crash.

Note that WebRAY Network Security has extracted the preceding
description block directly from the Ubuntu security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://usn.ubuntu.com/3967-1/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec-extra57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec-extra58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavcodec58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavdevice57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavdevice58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter-extra6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter-extra7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavfilter7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavformat57");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavformat58");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavresample3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavresample4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavutil55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libavutil56");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpostproc54");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libpostproc55");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswresample2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswresample3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswscale4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libswscale5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:19.04");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"Ubuntu Security Notice (C) 2019 Canonical, Inc. / NASL script (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Ubuntu Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("ubuntu.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Ubuntu/release");
if ( isnull(release) ) audit(AUDIT_OS_NOT, "Ubuntu");
release = chomp(release);
if (! ereg(pattern:"^(18\.04|18\.10|19\.04)$", string:release)) audit(AUDIT_OS_NOT, "Ubuntu 18.04 / 18.10 / 19.04", "Ubuntu " + release);
if ( ! get_kb_item("Host/Debian/dpkg-l") ) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Ubuntu", cpu);

flag = 0;

if (ubuntu_check(osver:"18.04", pkgname:"ffmpeg", pkgver:"7:3.4.6-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libavcodec-extra57", pkgver:"7:3.4.6-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libavcodec57", pkgver:"7:3.4.6-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libavdevice57", pkgver:"7:3.4.6-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libavfilter-extra6", pkgver:"7:3.4.6-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libavfilter6", pkgver:"7:3.4.6-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libavformat57", pkgver:"7:3.4.6-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libavresample3", pkgver:"7:3.4.6-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libavutil55", pkgver:"7:3.4.6-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libpostproc54", pkgver:"7:3.4.6-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libswresample2", pkgver:"7:3.4.6-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.04", pkgname:"libswscale4", pkgver:"7:3.4.6-0ubuntu0.18.04.1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"ffmpeg", pkgver:"7:4.0.4-0ubuntu1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libavcodec-extra58", pkgver:"7:4.0.4-0ubuntu1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libavcodec58", pkgver:"7:4.0.4-0ubuntu1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libavdevice58", pkgver:"7:4.0.4-0ubuntu1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libavfilter-extra7", pkgver:"7:4.0.4-0ubuntu1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libavfilter7", pkgver:"7:4.0.4-0ubuntu1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libavformat58", pkgver:"7:4.0.4-0ubuntu1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libavresample4", pkgver:"7:4.0.4-0ubuntu1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libavutil56", pkgver:"7:4.0.4-0ubuntu1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libpostproc55", pkgver:"7:4.0.4-0ubuntu1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libswresample3", pkgver:"7:4.0.4-0ubuntu1")) flag++;
if (ubuntu_check(osver:"18.10", pkgname:"libswscale5", pkgver:"7:4.0.4-0ubuntu1")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"ffmpeg", pkgver:"7:4.1.3-0ubuntu1")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"libavcodec-extra58", pkgver:"7:4.1.3-0ubuntu1")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"libavcodec58", pkgver:"7:4.1.3-0ubuntu1")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"libavdevice58", pkgver:"7:4.1.3-0ubuntu1")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"libavfilter-extra7", pkgver:"7:4.1.3-0ubuntu1")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"libavfilter7", pkgver:"7:4.1.3-0ubuntu1")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"libavformat58", pkgver:"7:4.1.3-0ubuntu1")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"libavresample4", pkgver:"7:4.1.3-0ubuntu1")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"libavutil56", pkgver:"7:4.1.3-0ubuntu1")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"libpostproc55", pkgver:"7:4.1.3-0ubuntu1")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"libswresample3", pkgver:"7:4.1.3-0ubuntu1")) flag++;
if (ubuntu_check(osver:"19.04", pkgname:"libswscale5", pkgver:"7:4.1.3-0ubuntu1")) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : ubuntu_report_get()
  );
  exit(0);
}
else
{
  tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ffmpeg / libavcodec-extra57 / libavcodec-extra58 / libavcodec57 / etc");
}
