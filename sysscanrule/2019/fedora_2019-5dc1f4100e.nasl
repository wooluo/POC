#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-5dc1f4100e.
#

include("compat.inc");

if (description)
{
  script_id(125181);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/10 16:04:13");

  script_cve_id("CVE-2019-11037");
  script_xref(name:"FEDORA", value:"2019-5dc1f4100e");

  script_name(english:"Fedora 29 : php-pecl-imagick (2019-5dc1f4100e)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**Version 3.4.4**

  - The 3.4.4 release is intended to be the last release
    (other than small bug fixes) that will support either
    PHP 5.x, or ImageMagick 6.x. The next planned release
    will be PHP > 7.0 and ImageMagick > 7.0 at least, if not
    higher.

  - **Added:**

  - function Imagick::optimizeImageTransparency()

  - METRIC_STRUCTURAL_SIMILARITY_ERROR

  - METRIC_STRUCTURAL_DISSIMILARITY_ERROR

  - COMPRESSION_ZSTD - https://github.com/facebook/zstd

  - COMPRESSION_WEBP

  - CHANNEL_COMPOSITE_MASK

  - FILTER_CUBIC_SPLINE - 'Define the lobes with the -define
    filter:lobes={2,3,4} (reference
    https://imagemagick.org/discourse-server/viewtopic.php?f
    =2&t=32506).'

  - Imagick now explicitly conflicts with the Gmagick
    extension.

  - **Fixes:**

  - Correct version check to make RemoveAlphaChannel and
    FlattenAlphaChannel be available when using Imagick with
    ImageMagick version 6.7.8-x

  - Bug 77128 - Imagick::setImageInterpolateMethod() not
    available on Windows

  - Prevent memory leak when ImagickPixel::__construct
    called after object instantiation.

  - Prevent segfault when ImagickPixel internal constructor
    not called.

  - Imagick::setResourceLimit support for values larger than
    2GB (2^31) on 32bit platforms.

  - Corrected memory overwrite in
    Imagick::colorDecisionListImage()

  - Bug 77791 - ImagickKernel::fromMatrix() out of bounds
    write.

  - **Deprecated:**

  - The following functions have been deprecated :

  - ImagickDraw, matte

  - Imagick::averageimages

  - Imagick::colorfloodfillimage

  - Imagick::filter

  - Imagick::flattenimages

  - Imagick::getimageattribute

  - Imagick::getimagechannelextrema

  - Imagick::getimageclipmask

  - Imagick::getimageextrema

  - Imagick::getimageindex

  - Imagick::getimagematte

  - Imagick::getimagemattecolor

  - Imagick::getimagesize

  - Imagick::mapimage

  - Imagick::mattefloodfillimage

  - Imagick::medianfilterimage

  - Imagick::mosaicimages

  - Imagick::orderedposterizeimage

  - Imagick::paintfloodfillimage

  - Imagick::paintopaqueimage

  - Imagick::painttransparentimage

  - Imagick::radialblurimage

  - Imagick::recolorimage

  - Imagick::reducenoiseimage

  - Imagick::roundcornersimage

  - Imagick::roundcorners

  - Imagick::setimageattribute

  - Imagick::setimagebias

  - Imagick::setimageclipmask

  - Imagick::setimageindex

  - Imagick::setimagemattecolor

  - Imagick::setimagebiasquantum

  - Imagick::setimageopacity

  - Imagick::transformimage

Note that WebRAY Network Security has extracted the preceding
description block directly from the Fedora update system website.
WebRAY has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-5dc1f4100e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-pecl-imagick package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-pecl-imagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:29");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/16");
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
if (! ereg(pattern:"^29([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 29", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC29", reference:"php-pecl-imagick-3.4.4-1.fc29")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-pecl-imagick");
}
