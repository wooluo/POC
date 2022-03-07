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
  script_id(124182);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/08 10:33:37");

  script_cve_id("CVE-2019-3855", "CVE-2019-3856", "CVE-2019-3857", "CVE-2019-3858", "CVE-2019-3859", "CVE-2019-3860", "CVE-2019-3861", "CVE-2019-3862", "CVE-2019-3863");

  script_name(english:"FreeBSD : libssh2 -- multiple issues (6e58e1e9-2636-413e-9f84-4c0e21143628)");
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
"libssh2 developers report :

- Defend against possible integer overflows in
comp_method_zlib_decomp.

- Defend against writing beyond the end of the payload in
_libssh2_transport_read().

- Sanitize padding_length - _libssh2_transport_read().

- This prevents an underflow resulting in a potential out-of-bounds
read if a server sends a too-large padding_length, possibly with
malicious intent.

- Prevent zero-byte allocation in sftp_packet_read() which could lead
to an out-of-bounds read.

- Check the length of data passed to sftp_packet_add() to prevent
out-of-bounds reads.

- Add a required_size parameter to sftp_packet_require et. al. to
require callers of these functions to handle packets that are too
short.

- Additional length checks to prevent out-of-bounds reads and writes
in _libssh2_packet_add()."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/libssh2/libssh2/releases/tag/libssh2-1.8.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://libssh2.org/CVE-2019-3855.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://libssh2.org/CVE-2019-3856.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://libssh2.org/CVE-2019-3857.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://libssh2.org/CVE-2019-3858.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://libssh2.org/CVE-2019-3859.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://libssh2.org/CVE-2019-3860.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://libssh2.org/CVE-2019-3861.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://libssh2.org/CVE-2019-3862.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://libssh2.org/CVE-2019-3863.html"
  );
  # https://vuxml.freebsd.org/freebsd/6e58e1e9-2636-413e-9f84-4c0e21143628.html
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libssh2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-c6-libssh2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-c7-libssh2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/19");
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

if (pkg_test(save_report:TRUE, pkg:"libssh2<1.8.1,3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-c6-libssh2<1.4.2_7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-c7-libssh2<1.4.3_3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
