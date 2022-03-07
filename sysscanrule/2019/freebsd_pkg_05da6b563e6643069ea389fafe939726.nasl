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
  script_id(122959);
  script_version("1.5");
  script_cvs_date("Date: 2019/07/23 10:11:24");

  script_cve_id("CVE-2019-9788", "CVE-2019-9789", "CVE-2019-9790", "CVE-2019-9791", "CVE-2019-9792", "CVE-2019-9793", "CVE-2019-9794", "CVE-2019-9795", "CVE-2019-9796", "CVE-2019-9797", "CVE-2019-9798", "CVE-2019-9799", "CVE-2019-9801", "CVE-2019-9802", "CVE-2019-9803", "CVE-2019-9804", "CVE-2019-9805", "CVE-2019-9806", "CVE-2019-9807", "CVE-2019-9808", "CVE-2019-9809");

  script_name(english:"FreeBSD : mozilla -- multiple vulnerabilities (05da6b56-3e66-4306-9ea3-89fafe939726)");
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

CVE-2019-9790: Use-after-free when removing in-use DOM elements

CVE-2019-9791: Type inference is incorrect for constructors entered
through on-stack replacement with IonMonkey

CVE-2019-9792: IonMonkey leaks JS_OPTIMIZED_OUT magic value to script

CVE-2019-9793: Improper bounds checks when Spectre mitigations are
disabled

CVE-2019-9794: Command line arguments not discarded during execution

CVE-2019-9795: Type-confusion in IonMonkey JIT compiler

CVE-2019-9796: Use-after-free with SMIL animation controller

CVE-2019-9797: Cross-origin theft of images with createImageBitmap

CVE-2019-9798: Library is loaded from world-writable APITRACE_LIB
location

CVE-2019-9799: Information disclosure via IPC channel messages

CVE-2019-9801: Windows programs that are not 'URL Handlers' are
exposed to web content

CVE-2019-9802: Chrome process information leak

CVE-2019-9803: Upgrade-Insecure-Requests incorrectly enforced for
same-origin navigation

CVE-2019-9804: Code execution through 'Copy as cURL' in Firefox
Developer Tools on macOS

CVE-2019-9805: Potential use of uninitialized memory in Prio

CVE-2019-9806: Denial of service through successive FTP authorization
prompts

CVE-2019-9807: Text sent through FTP connection can be incorporated
into alert messages

CVE-2019-9809: Denial of service through FTP modal alert error
messages

CVE-2019-9808: WebRTC permissions can display incorrect origin with
data: and blob: URLs

CVE-2019-9789: Memory safety bugs fixed in Firefox 66

CVE-2019-9788: Memory safety bugs fixed in Firefox 66 and Firefox ESR
60.6"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2019-07/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/advisories/mfsa2019-08/"
  );
  # https://vuxml.freebsd.org/freebsd/05da6b56-3e66-4306-9ea3-89fafe939726.html
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/20");
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

if (pkg_test(save_report:TRUE, pkg:"firefox<66.0_3,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"waterfox<56.2.9")) flag++;
if (pkg_test(save_report:TRUE, pkg:"seamonkey<2.53.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-seamonkey<2.53.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"firefox-esr<60.6.0,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-firefox<60.6.0,2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libxul<60.6.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"thunderbird<60.6.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-thunderbird<60.6.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
