#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2019 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
# 
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

include("compat.inc");

if (description)
{
  script_id(125614);
  script_version("1.4");
  script_cvs_date("Date: 2019/07/10 16:04:13");

  script_cve_id("CVE-2019-10131", "CVE-2019-10649", "CVE-2019-10650", "CVE-2019-10714", "CVE-2019-11470", "CVE-2019-11472", "CVE-2019-11597", "CVE-2019-11598", "CVE-2019-7175", "CVE-2019-7395", "CVE-2019-7396", "CVE-2019-7397", "CVE-2019-7398", "CVE-2019-9956");

  script_name(english:"FreeBSD : ImageMagick -- multiple vulnerabilities (183d700e-ec70-487e-a9c4-632324afa934)");
  script_summary(english:"Checks for updated packages in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote FreeBSD host is missing one or more security-related
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"cvedetails.com reports :

CVE-2019-7175: In ImageMagick before 7.0.8-25, some memory leaks exist
in DecodeImage in coders/pcd.c.

CVE-2019-7395: In ImageMagick before 7.0.8-25, a memory leak exists in
WritePSDChannel in coders/psd.c.

CVE-2019-7396: In ImageMagick before 7.0.8-25, a memory leak exists in
ReadSIXELImage in coders/sixel.c.

CVE-2019-7397: In ImageMagick before 7.0.8-25 and GraphicsMagick
through 1.3.31, several memory leaks exist in WritePDFImage in
coders/pdf.c.

CVE-2019-7398: In ImageMagick before 7.0.8-25, a memory leak exists in
WriteDIBImage in coders/dib.c.

CVE-2019-9956: In ImageMagick 7.0.8-35 Q16, there is a stack-based
buffer overflow in the function PopHexPixel of coders/ps.c, which
allows an attacker to cause a denial of service or code execution via
a crafted image file.

CVE-2019-10131: An off-by-one read vulnerability was discovered in
ImageMagick before version 7.0.7-28 in the formatIPTCfromBuffer
function in coders/meta.c. A local attacker may use this flaw to read
beyond the end of the buffer or to crash the program.

CVE-2019-10649: In ImageMagick 7.0.8-36 Q16, there is a memory leak in
the function SVGKeyValuePairs of coders/svg.c, which allows an
attacker to cause a denial of service via a crafted image file.

CVE-2019-10650: In ImageMagick 7.0.8-36 Q16, there is a heap-based
buffer over-read in the function WriteTIFFImage of coders/tiff.c,
which allows an attacker to cause a denial of service or information
disclosure via a crafted image file.

CVE-2019-10714: LocaleLowercase in MagickCore/locale.c in ImageMagick
before 7.0.8-32 allows out-of-bounds access, leading to a SIGSEGV.

CVE-2019-11470: The cineon parsing component in ImageMagick 7.0.8-26
Q16 allows attackers to cause a denial-of-service (uncontrolled
resource consumption) by crafting a Cineon image with an incorrect
claimed image size. This occurs because ReadCINImage in coders/cin.c
lacks a check for insufficient image data in a file.

CVE-2019-11472: ReadXWDImage in coders/xwd.c in the XWD image parsing
component of ImageMagick 7.0.8-41 Q16 allows attackers to cause a
denial-of-service (divide-by-zero error) by crafting an XWD image file
in which the header indicates neither LSB first nor MSB first.

CVE-2019-11597: In ImageMagick 7.0.8-43 Q16, there is a heap-based
buffer over-read in the function WriteTIFFImage of coders/tiff.c,
which allows an attacker to cause a denial of service or possibly
information disclosure via a crafted image file.

CVE-2019-11598: In ImageMagick 7.0.8-40 Q16, there is a heap-based
buffer over-read in the function WritePNMImage of coders/pnm.c, which
allows an attacker to cause a denial of service or possibly
information disclosure via a crafted image file. This is related to
SetGrayscaleImage in MagickCore/quantize.c."
  );
  # https://www.cvedetails.com/vulnerability-list/vendor_id-1749/Imagemagick.html
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # https://vuxml.freebsd.org/freebsd/183d700e-ec70-487e-a9c4-632324afa934.html
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ImageMagick6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ImageMagick6-nox11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ImageMagick7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ImageMagick7-nox11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/31");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"ImageMagick7<7.0.8.47")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ImageMagick7-nox11<7.0.8.47")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ImageMagick6<6.9.10.47,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ImageMagick6-nox11<6.9.10.47,1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
