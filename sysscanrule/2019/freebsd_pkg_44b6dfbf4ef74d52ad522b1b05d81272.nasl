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
  script_id(125346);
  script_version("1.5");
  script_cvs_date("Date: 2019/07/26 16:46:13");

  script_cve_id("CVE-2019-11691", "CVE-2019-11692", "CVE-2019-11693", "CVE-2019-11694", "CVE-2019-11695", "CVE-2019-11696", "CVE-2019-11697", "CVE-2019-11698", "CVE-2019-11699", "CVE-2019-11700", "CVE-2019-11701", "CVE-2019-7317", "CVE-2019-9800", "CVE-2019-9814", "CVE-2019-9815", "CVE-2019-9816", "CVE-2019-9817", "CVE-2019-9818", "CVE-2019-9819", "CVE-2019-9820", "CVE-2019-9821");

  script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (44b6dfbf-4ef7-4d52-ad52-2b1b05d81272)");
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
"Mozilla Foundation reports :

CVE-2019-9815: Disable hyperthreading on content JavaScript threads on
macOS

CVE-2019-9816: Type confusion with object groups and UnboxedObjects

CVE-2019-9817: Stealing of cross-domain images using canvas

CVE-2019-9818: Use-after-free in crash generation server

CVE-2019-9819: Compartment mismatch with fetch API

CVE-2019-9820: Use-after-free of ChromeEventHandler by DocShell

CVE-2019-9821: Use-after-free in AssertWorkerThread

CVE-2019-11691: Use-after-free in XMLHttpRequest

CVE-2019-11692: Use-after-free removing listeners in the event
listener manager

CVE-2019-11693: Buffer overflow in WebGL bufferdata on Linux

CVE-2019-7317: Use-after-free in png_image_free of libpng library

CVE-2019-11694: Uninitialized memory memory leakage in Windows sandbox

CVE-2019-11695: Custom cursor can render over user interface outside
of web content

CVE-2019-11696: Java web start .JNLP files are not recognized as
executable files for download prompts

CVE-2019-11697: Pressing key combinations can bypass installation
prompt delays and install extensions

CVE-2019-11698: Theft of user history data through drag and drop of
hyperlinks to and from bookmarks

CVE-2019-11700: res: protocol can be used to open known local files

CVE-2019-11699: Incorrect domain name highlighting during page
navigation

CVE-2019-11701: webcal: protocol default handler loads vulnerable web
page

CVE-2019-9814: Memory safety bugs fixed in Firefox 67

CVE-2019-9800: Memory safety bugs fixed in Firefox 67 and Firefox ESR
60.7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2019-13/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2019-14/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2019-15/"
  );
  # https://vuxml.freebsd.org/freebsd/44b6dfbf-4ef7-4d52-ad52-2b1b05d81272.html
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:firefox-esr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libxul");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:waterfox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/23");
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

if (pkg_test(save_report:TRUE, pkg:"firefox<67.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"waterfox<56.2.10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"seamonkey<2.53.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-seamonkey<2.53.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox-esr<60.7.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox<60.7.0,2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libxul<60.7.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird<60.7.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird<60.7.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
