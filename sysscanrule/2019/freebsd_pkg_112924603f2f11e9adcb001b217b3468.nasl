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
  script_id(122630);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/10 16:04:13");

  script_cve_id("CVE-2019-9170", "CVE-2019-9171", "CVE-2019-9172", "CVE-2019-9174", "CVE-2019-9175", "CVE-2019-9176", "CVE-2019-9178", "CVE-2019-9179", "CVE-2019-9217", "CVE-2019-9219", "CVE-2019-9220", "CVE-2019-9221", "CVE-2019-9222", "CVE-2019-9223", "CVE-2019-9224", "CVE-2019-9225", "CVE-2019-9485");

  script_name(english:"FreeBSD : Gitlab -- Multiple vulnerabilities (11292460-3f2f-11e9-adcb-001b217b3468)");
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
"Gitlab reports :

Arbitrary file read via MergeRequestDiff

CSRF add Kubernetes cluster integration

Blind SSRF in prometheus integration

Merge request information disclosure

IDOR milestone name information disclosure

Burndown chart information disclosure

Private merge request titles in public project information disclosure

Private namespace disclosure in email notification when issue is moved

Milestone name disclosure

Issue board name disclosure

NPM automatic package referencer

Path traversal snippet mover

Information disclosure repo existence

Issue DoS via Mermaid

Privilege escalation impersonate user"
  );
  # https://about.gitlab.com/2019/03/04/security-release-gitlab-11-dot-8-dot-1-released/
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # https://vuxml.freebsd.org/freebsd/11292460-3f2f-11e9-adcb-001b217b3468.html
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gitlab-ce");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/06");
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

if (pkg_test(save_report:TRUE, pkg:"gitlab-ce>=11.8.0<11.8.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gitlab-ce>=11.7.0<11.7.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gitlab-ce>=2.9.0<11.6.10")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
