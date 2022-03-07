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
  script_id(122571);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/02 10:22:10");

  script_cve_id("CVE-2019-1559", "CVE-2019-5737", "CVE-2019-5739");

  script_name(english:"FreeBSD : Node.js -- multiple vulnerabilities (b71d7193-3c54-11e9-a3f9-00155d006b02)");
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
"Node.js reports :

Updates are now available for all active Node.js release lines. In
addition to fixes for security flaws in Node.js, they also include
upgrades of Node.js 6 and 8 to OpenSSL 1.0.2r which contains a fix for
a moderate severity security vulnerability.

For these releases, we have decided to withhold the fix for the
Misinterpretation of Input (CWE-115) flaw mentioned in the original
announcement. This flaw is very low severity and we are not satisfied
that we had a complete and stable fix ready for release. We will be
seeking to address this flaw via alternate mechanisms in the near
future. In addition, we have introduced an additional CVE for a change
in Node.js 6 that we have decided to classify as a Denial of Service
(CWE-400) flaw.

We recommend that all Node.js users upgrade to a version listed below
as soon as possible. OpenSSL: 0-byte record padding oracle
(CVE-2019-1559) OpenSSL 1.0.2r contains a fix for CVE-2019-1559 and is
included in the releases for Node.js versions 6 and 8 only. Node.js 10
and 11 are not impacted by this vulnerability as they use newer
versions of OpenSSL which do not contain the flaw.

Under certain circumstances, a TLS server can be forced to respond
differently to a client if a zero-byte record is received with an
invalid padding compared to a zero-byte record with an invalid MAC.
This can be used as the basis of a padding oracle attack to decrypt
data.

Only TLS connections using certain ciphersuites executing under
certain conditions are exploitable. We are currently unable to
determine whether the use of OpenSSL in Node.js exposes this
vulnerability. We are taking a cautionary approach and recommend the
same for users. For more information, see the advisory and a detailed
write-up by the reporters of the vulnerability."
  );
  # https://nodejs.org/en/blog/vulnerability/february-2019-security-releases/
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # https://vuxml.freebsd.org/freebsd/b71d7193-3c54-11e9-a3f9-00155d006b02.html
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/04");
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

if (pkg_test(save_report:TRUE, pkg:"node<11.10.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node10<10.15.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node8<8.15.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node6<6.17.0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
