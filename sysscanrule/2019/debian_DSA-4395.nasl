#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4395. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122272);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/15 14:20:30");

  script_cve_id("CVE-2018-17481", "CVE-2019-5754", "CVE-2019-5755", "CVE-2019-5756", "CVE-2019-5757", "CVE-2019-5758", "CVE-2019-5759", "CVE-2019-5760", "CVE-2019-5762", "CVE-2019-5763", "CVE-2019-5764", "CVE-2019-5765", "CVE-2019-5766", "CVE-2019-5767", "CVE-2019-5768", "CVE-2019-5769", "CVE-2019-5770", "CVE-2019-5772", "CVE-2019-5773", "CVE-2019-5774", "CVE-2019-5775", "CVE-2019-5776", "CVE-2019-5777", "CVE-2019-5778", "CVE-2019-5779", "CVE-2019-5780", "CVE-2019-5781", "CVE-2019-5782", "CVE-2019-5783", "CVE-2019-5784");
  script_xref(name:"DSA", value:"4395");

  script_name(english:"Debian DSA-4395-1 : chromium - security update");
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

  - CVE-2018-17481
    A use-after-free issue was discovered in the pdfium
    library.

  - CVE-2019-5754
    Klzgrad discovered an error in the QUIC networking
    implementation.

  - CVE-2019-5755
    Jay Bosamiya discovered an implementation error in the
    v8 JavaScript library.

  - CVE-2019-5756
    A use-after-free issue was discovered in the pdfium
    library.

  - CVE-2019-5757
    Alexandru Pitis discovered a type confusion error in the
    SVG image format implementation.

  - CVE-2019-5758
    Zhe Jin discovered a use-after-free issue in
    blink/webkit.

  - CVE-2019-5759
    Almog Benin discovered a use-after-free issue when
    handling HTML pages containing select elements.

  - CVE-2019-5760
    Zhe Jin discovered a use-after-free issue in the WebRTC
    implementation.

  - CVE-2019-5762
    A use-after-free issue was discovered in the pdfium
    library.

  - CVE-2019-5763
    Guang Gon discovered an input validation error in the v8
    JavaScript library.

  - CVE-2019-5764
    Eyal Itkin discovered a use-after-free issue in the
    WebRTC implementation.

  - CVE-2019-5765
    Sergey Toshin discovered a policy enforcement error.

  - CVE-2019-5766
    David Erceg discovered a policy enforcement error.

  - CVE-2019-5767
    Haoran Lu, Yifan Zhang, Luyi Xing, and Xiaojing Liao
    reported an error in the WebAPKs user interface.

  - CVE-2019-5768
    Rob Wu discovered a policy enforcement error in the
    developer tools.

  - CVE-2019-5769
    Guy Eshel discovered an input validation error in
    blink/webkit.

  - CVE-2019-5770
    hemidallt discovered a buffer overflow issue in the
    WebGL implementation.

  - CVE-2019-5772
    Zhen Zhou discovered a use-after-free issue in the
    pdfium library.

  - CVE-2019-5773
    Yongke Wong discovered an input validation error in the
    IndexDB implementation.

  - CVE-2019-5774
    Junghwan Kang and Juno Im discovered an input validation
    error in the SafeBrowsing implementation.

  - CVE-2019-5775
    evil1m0 discovered a policy enforcement error.

  - CVE-2019-5776
    Lnyas Zhang discovered a policy enforcement error.

  - CVE-2019-5777
    Khalil Zhani discovered a policy enforcement error.

  - CVE-2019-5778
    David Erceg discovered a policy enforcement error in the
    Extensions implementation.

  - CVE-2019-5779
    David Erceg discovered a policy enforcement error in the
    ServiceWorker implementation.

  - CVE-2019-5780
    Andreas Hegenberg discovered a policy enforcement error.

  - CVE-2019-5781
    evil1m0 discovered a policy enforcement error.

  - CVE-2019-5782
    Qixun Zhao discovered an implementation error in the v8
    JavaScript library.

  - CVE-2019-5783
    Shintaro Kobori discovered an input validation error in
    the developer tools.

  - CVE-2019-5784
    Lucas Pinheiro discovered an implementation error in the
    v8 JavaScript library."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-17481"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5754"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5756"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5757"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5759"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5763"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5764"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5765"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5766"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5768"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5773"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5774"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5780"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5781"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-5784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/chromium"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/chromium"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4395"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium packages.

For the stable distribution (stretch), these problems have been fixed
in version 72.0.3626.96-1~deb9u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/19");
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
if (deb_check(release:"9.0", prefix:"chromedriver", reference:"72.0.3626.96-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium", reference:"72.0.3626.96-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-driver", reference:"72.0.3626.96-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-l10n", reference:"72.0.3626.96-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-shell", reference:"72.0.3626.96-1~deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"chromium-widevine", reference:"72.0.3626.96-1~deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
