#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124940);
  script_version("1.3");
  script_cvs_date("Date: 2019/06/27 13:33:25");

  script_cve_id(
    "CVE-2013-1960",
    "CVE-2013-1961",
    "CVE-2013-4232",
    "CVE-2013-4243",
    "CVE-2013-4244",
    "CVE-2014-8127",
    "CVE-2014-8129",
    "CVE-2014-8130",
    "CVE-2014-9330",
    "CVE-2014-9655",
    "CVE-2015-1547",
    "CVE-2015-8870",
    "CVE-2016-3632",
    "CVE-2016-3945",
    "CVE-2016-3990",
    "CVE-2016-3991",
    "CVE-2016-6223",
    "CVE-2016-9532",
    "CVE-2018-19210",
    "CVE-2019-6128",
    "CVE-2019-7663"
  );
  script_bugtraq_id(
    59607,
    59609,
    61695,
    61849,
    62019,
    62082,
    71789,
    72323,
    72352,
    72353,
    73438,
    73441
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : libtiff (EulerOS-SA-2019-1437)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libtiff package installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - Heap-based buffer overflow in the readgifimage function
    in the gif2tiff tool in libtiff 4.0.3 and earlier
    allows remote attackers to cause a denial of service
    (crash) and possibly execute arbitrary code via a
    crafted height and width values in a GIF
    image.(CVE-2013-4243)

  - Integer overflow in tools/bmp2tiff.c in LibTIFF before
    4.0.4 allows remote attackers to cause a denial of
    service (heap-based buffer over-read), or possibly
    obtain sensitive information from process memory, via
    crafted width and length values in RLE4 or RLE8 data in
    a BMP file.(CVE-2015-8870)

  - LibTIFF 4.0.3 allows remote attackers to cause a denial
    of service (out-of-bounds read and crash) via a crafted
    TIFF image to the (1) checkInkNamesString function in
    tif_dir.c in the thumbnail tool, (2) compresscontig
    function in tiff2bw.c in the tiff2bw tool, (3)
    putcontig8bitCIELab function in tif_getimage.c in the
    tiff2rgba tool, LZWPreDecode function in tif_lzw.c in
    the (4) tiff2ps or (5) tiffdither tool, (6) NeXTDecode
    function in tif_next.c in the tiffmedian tool, or (7)
    TIFFWriteDirectoryTagLongLong8Array function in
    tif_dirwrite.c in the tiffset tool.(CVE-2014-8127)

  - Use-after-free vulnerability in the
    t2p_readwrite_pdf_image function in tools/tiff2pdf.c in
    libtiff 4.0.3 allows remote attackers to cause a denial
    of service (crash) or possibly execute arbitrary code
    via a crafted TIFF image.(CVE-2013-4232)

  - Integer overflow in the writeBufferToSeparateStrips
    function in tiffcrop.c in LibTIFF before 4.0.7 allows
    remote attackers to cause a denial of service
    (out-of-bounds read) via a crafted tif
    file.(CVE-2016-9532)

  - Multiple integer overflows in the (1) cvt_by_strip and
    (2) cvt_by_tile functions in the tiff2rgba tool in
    LibTIFF 4.0.6 and earlier, when -b mode is enabled,
    allow remote attackers to cause a denial of service
    (crash) or execute arbitrary code via a crafted TIFF
    image, which triggers an out-of-bounds
    write.(CVE-2016-3945)

  - The (1) putcontig8bitYCbCr21tile function in
    tif_getimage.c or (2) NeXTDecode function in tif_next.c
    in LibTIFF allows remote attackers to cause a denial of
    service (uninitialized memory access) via a crafted
    TIFF image, as demonstrated by libtiff-cvs-1.tif and
    libtiff-cvs-2.tif.(CVE-2014-9655)

  - A flaw was discovered in the bmp2tiff utility. By
    tricking a user into processing a specially crafted
    file, a remote attacker could exploit this flaw to
    cause a crash or memory corruption and, possibly,
    execute arbitrary code with the privileges of the user
    running the libtiff tool.(CVE-2014-9330)

  - The TIFFReadRawStrip1 and TIFFReadRawTile1 functions in
    tif_read.c in libtiff before 4.0.7 allows remote
    attackers to cause a denial of service (crash) or
    possibly obtain sensitive information via a negative
    index in a file-content buffer.(CVE-2016-6223)

  - The _TIFFmalloc function in tif_unix.c in LibTIFF 4.0.3
    does not reject a zero size, which allows remote
    attackers to cause a denial of service (divide-by-zero
    error and application crash) via a crafted TIFF image
    that is mishandled by the TIFFWriteScanline function in
    tif_write.c, as demonstrated by
    tiffdither.(CVE-2014-8130)

  - Heap-based buffer overflow in the
    t2p_process_jpeg_strip function in tiff2pdf in libtiff
    4.0.3 and earlier allows remote attackers to cause a
    denial of service (crash) and possibly execute
    arbitrary code via a crafted TIFF image
    file.(CVE-2013-1960)

  - Stack-based buffer overflow in the t2p_write_pdf_page
    function in tiff2pdf in libtiff before 4.0.3 allows
    remote attackers to cause a denial of service
    (application crash) via a crafted image length and
    resolution in a TIFF image file.(CVE-2013-1961)

  - Heap-based buffer overflow in the loadImage function in
    the tiffcrop tool in LibTIFF 4.0.6 and earlier allows
    remote attackers to cause a denial of service
    (out-of-bounds write) or execute arbitrary code via a
    crafted TIFF image with zero tiles.(CVE-2016-3991)

  - Heap-based buffer overflow in the horizontalDifference8
    function in tif_pixarlog.c in LibTIFF 4.0.6 and earlier
    allows remote attackers to cause a denial of service
    (crash) or execute arbitrary code via a crafted TIFF
    image to tiffcp.(CVE-2016-3990)

  - LibTIFF 4.0.3 allows remote attackers to cause a denial
    of service (out-of-bounds write) or possibly have
    unspecified other impact via a crafted TIFF image, as
    demonstrated by failure of tif_next.c to verify that
    the BitsPerSample value is 2, and the
    t2p_sample_lab_signed_to_unsigned function in
    tiff2pdf.c.(CVE-2014-8129)

  - The LZW decompressor in the gif2tiff tool in libtiff
    4.0.3 and earlier allows context-dependent attackers to
    cause a denial of service (out-of-bounds write and
    crash) or possibly execute arbitrary code via a crafted
    GIF image.(CVE-2013-4244)

  - The _TIFFVGetField function in tif_dirinfo.c in LibTIFF
    4.0.6 and earlier allows remote attackers to cause a
    denial of service (out-of-bounds write) or execute
    arbitrary code via a crafted TIFF image.(CVE-2016-3632)

  - The NeXTDecode function in tif_next.c in LibTIFF allows
    remote attackers to cause a denial of service
    (uninitialized memory access) via a crafted TIFF image,
    as demonstrated by libtiff5.tif.(CVE-2015-1547)

  - In LibTIFF 4.0.9, there is a NULL pointer dereference
    in the TIFFWriteDirectorySec function in tif_dirwrite.c
    that will lead to a denial of service attack, as
    demonstrated by tiffset.(CVE-2018-19210)

  - The TIFFFdOpen function in tif_unix.c in LibTIFF 4.0.10
    has a memory leak, as demonstrated by
    pal2rgb.(CVE-2019-6128)

  - An Invalid Address dereference was discovered in
    TIFFWriteDirectoryTagTransferfunction in
    libtiff/tif_dirwrite.c in LibTIFF 4.0.10, affecting the
    cpSeparateBufToContigBuf function in tiffcp.c. Remote
    attackers could leverage this vulnerability to cause a
    denial-of-service via a crafted tiff file. This is
    different from CVE-2018-12900.(CVE-2019-7663)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1437
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected libtiff packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libtiff");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["libtiff-4.0.3-27.h8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff");
}
