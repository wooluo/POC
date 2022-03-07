#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4500. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127868);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/20 11:58:13");

  script_cve_id("CVE-2019-5805", "CVE-2019-5806", "CVE-2019-5807", "CVE-2019-5808", "CVE-2019-5809", "CVE-2019-5810", "CVE-2019-5811", "CVE-2019-5813", "CVE-2019-5814", "CVE-2019-5815", "CVE-2019-5818", "CVE-2019-5819", "CVE-2019-5820", "CVE-2019-5821", "CVE-2019-5822", "CVE-2019-5823", "CVE-2019-5824", "CVE-2019-5825", "CVE-2019-5826", "CVE-2019-5827", "CVE-2019-5828", "CVE-2019-5829", "CVE-2019-5830", "CVE-2019-5831", "CVE-2019-5832", "CVE-2019-5833", "CVE-2019-5834", "CVE-2019-5836", "CVE-2019-5837", "CVE-2019-5838", "CVE-2019-5839", "CVE-2019-5840", "CVE-2019-5842", "CVE-2019-5847", "CVE-2019-5848", "CVE-2019-5849", "CVE-2019-5850", "CVE-2019-5851", "CVE-2019-5852", "CVE-2019-5853", "CVE-2019-5854", "CVE-2019-5855", "CVE-2019-5856", "CVE-2019-5857", "CVE-2019-5858", "CVE-2019-5859", "CVE-2019-5860", "CVE-2019-5861", "CVE-2019-5862", "CVE-2019-5864", "CVE-2019-5865", "CVE-2019-5867", "CVE-2019-5868");
  script_xref(name:"DSA", value:"4500");

  script_name(english:"Debian DSA-4500-1 : chromium - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the chromium web
browser.

  - CVE-2019-5805
    A use-after-free issue was discovered in the pdfium
    library.

  - CVE-2019-5806
    Wen Xu discovered an integer overflow issue in the Angle
    library.

  - CVE-2019-5807
    TimGMichaud discovered a memory corruption issue in the
    v8 JavaScript library.

  - CVE-2019-5808
    cloudfuzzer discovered a use-after-free issue in
    Blink/Webkit.

  - CVE-2019-5809
    Mark Brand discovered a use-after-free issue in
    Blink/Webkit.

  - CVE-2019-5810
    Mark Amery discovered an information disclosure issue.

  - CVE-2019-5811
    Jun Kokatsu discovered a way to bypass the Cross-Origin
    Resource Sharing feature.

  - CVE-2019-5813
    Aleksandar Nikolic discovered an out-of-bounds read
    issue in the v8 JavaScript library.

  - CVE-2019-5814
    @AaylaSecura1138 discovered a way to bypass the
    Cross-Origin Resource Sharing feature.

  - CVE-2019-5815
    Nicolas Gregoire discovered a buffer overflow issue in
    Blink/Webkit.

  - CVE-2019-5818
    Adrian Tolbaru discovered an uninitialized value issue.

  - CVE-2019-5819
    Svyat Mitin discovered an error in the developer tools.

  - CVE-2019-5820
    pdknsk discovered an integer overflow issue in the
    pdfium library.

  - CVE-2019-5821
    pdknsk discovered another integer overflow issue in the
    pdfium library.

  - CVE-2019-5822
    Jun Kokatsu discovered a way to bypass the Cross-Origin
    Resource Sharing feature.

  - CVE-2019-5823
    David Erceg discovered a navigation error.

  - CVE-2019-5824
    leecraso and Guang Gong discovered an error in the media
    player.

  - CVE-2019-5825
    Genming Liu, Jianyu Chen, Zhen Feng, and Jessica Liu
    discovered an out-of-bounds write issue in the v8
    JavaScript library.

  - CVE-2019-5826
    Genming Liu, Jianyu Chen, Zhen Feng, and Jessica Liu
    discovered a use-after-free issue.

  - CVE-2019-5827
    mlfbrown discovered an out-of-bounds read issue in the
    sqlite library.

  - CVE-2019-5828
    leecraso and Guang Gong discovered a use-after-free
    issue.

  - CVE-2019-5829
    Lucas Pinheiro discovered a use-after-free issue.

  - CVE-2019-5830
    Andrew Krashichkov discovered a credential error in the
    Cross-Origin Resource Sharing feature.

  - CVE-2019-5831
    yngwei discovered a map error in the v8 JavaScript
    library.

  - CVE-2019-5832
    Sergey Shekyan discovered an error in the Cross-Origin
    Resource Sharing feature.

  - CVE-2019-5833
    Khalil Zhani discovered a user interface error.

  - CVE-2019-5834
    Khalil Zhani discovered a URL spoofing issue.

  - CVE-2019-5836
    Omair discovered a buffer overflow issue in the Angle
    library.

  - CVE-2019-5837
    Adam Iawniuk discovered an information disclosure issue.

  - CVE-2019-5838
    David Erceg discovered an error in extension
    permissions.

  - CVE-2019-5839
    Masato Kinugawa discovered implementation errors in
    Blink/Webkit.

  - CVE-2019-5840
    Eliya Stein and Jerome Dangu discovered a way to bypass
    the popup blocker.

  - CVE-2019-5842
    BUGFENSE discovered a use-after-free issue in
    Blink/Webkit.

  - CVE-2019-5847
    m3plex discovered an error in the v8 JavaScript library.

  - CVE-2019-5848
    Mark Amery discovered an information disclosure issue.

  - CVE-2019-5849
    Zhen Zhou discovered an out-of-bounds read in the Skia
    library.

  - CVE-2019-5850
    Brendon Tiszka discovered a use-after-free issue in the
    offline page fetcher.

  - CVE-2019-5851
    Zhe Jin discovered a use-after-poison issue.

  - CVE-2019-5852
    David Erceg discovered an information disclosure issue.

  - CVE-2019-5853
    Yngwei and sakura discovered a memory corruption issue.

  - CVE-2019-5854
    Zhen Zhou discovered an integer overflow issue in the
    pdfium library.

  - CVE-2019-5855
    Zhen Zhou discovered an integer overflow issue in the
    pdfium library.

  - CVE-2019-5856
    Yongke Wang discovered an error related to filesystem:
    URI permissions.

  - CVE-2019-5857
    cloudfuzzer discovered a way to crash chromium.

  - CVE-2019-5858
    evil1m0 discovered an information disclosure issue.

  - CVE-2019-5859
    James Lee discovered a way to launch alternative
    browsers.

  - CVE-2019-5860
    A use-after-free issue was discovered in the v8
    JavaScript library.

  - CVE-2019-5861
    Robin Linus discovered an error determining click
    location.

  - CVE-2019-5862
    Jun Kokatsu discovered an error in the AppCache
    implementation.

  - CVE-2019-5864
    Devin Grindle discovered an error in the Cross-Origin
    Resourse Sharing feature for extensions.

  - CVE-2019-5865
    Ivan Fratric discovered a way to bypass the site
    isolation feature.

  - CVE-2019-5867
    Lucas Pinheiro discovered an out-of-bounds read issue in
    the v8 JavaScript library.

  - CVE-2019-5868
    banananapenguin discovered a use-after-free issue in the
    v8 JavaScript library."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5806"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5807"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5808"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5809"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5810"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5814"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5819"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5823"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5824"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5828"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5833"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5834"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5838"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5842"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5849"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5852"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5854"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5856"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5859"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5861"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5862"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5865"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/chromium"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/buster/chromium"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4500"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium packages.

For the stable distribution (buster), these problems have been fixed
in version 76.0.3809.100-1~deb10u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/14");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"10.0", prefix:"chromium", reference:"76.0.3809.100-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-common", reference:"76.0.3809.100-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-driver", reference:"76.0.3809.100-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-l10n", reference:"76.0.3809.100-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-sandbox", reference:"76.0.3809.100-1~deb10u1")) flag++;
if (deb_check(release:"10.0", prefix:"chromium-shell", reference:"76.0.3809.100-1~deb10u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
