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
  script_id(121522);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/10 16:04:13");

  script_cve_id("CVE-2018-16476", "CVE-2019-6781", "CVE-2019-6782", "CVE-2019-6783", "CVE-2019-6784", "CVE-2019-6785", "CVE-2019-6786", "CVE-2019-6787", "CVE-2019-6788", "CVE-2019-6789", "CVE-2019-6790", "CVE-2019-6791", "CVE-2019-6792", "CVE-2019-6793", "CVE-2019-6794", "CVE-2019-6795", "CVE-2019-6796", "CVE-2019-6797", "CVE-2019-6960", "CVE-2019-6995", "CVE-2019-6996", "CVE-2019-6997", "CVE-2019-7155", "CVE-2019-7176");

  script_name(english:"FreeBSD : Gitlab -- Multiple vulnerabilities (467b7cbe-257d-11e9-8573-001b217b3468)");
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

Remote Command Execution via GitLab Pages

Covert Redirect to Steal GitHub/Bitbucket Tokens

Remote Mirror Branches Leaked by Git Transfer Refs

Denial of Service with Markdown

Guests Can View List of Group Merge Requests

Guest Can View Merge Request Titles via System Notes

Persistent XSS via KaTeX

Emails Sent to Unauthorized Users

Hyperlink Injection in Notification Emails

Unauthorized Access to LFS Objects

Trigger Token Exposure

Upgrade Rails to 5.0.7.1 and 4.2.11

Contributed Project Information Visible in Private Profile

Imported Project Retains Prior Visibility Setting

Error disclosure on Project Import

Persistent XSS in User Status

Last Commit Status Leaked to Guest Users

Mitigations for IDN Homograph and RTLO Attacks

Access to Internal Wiki When External Wiki Enabled

User Can Comment on Locked Project Issues

Unauthorized Reaction Emojis by Guest Users

User Retains Project Role After Removal from Private Group

GitHub Token Leaked to Maintainers

Unauthenticated Blind SSRF in Jira Integration

Unauthorized Access to Group Membership

Validate SAML Response in Group SAML SSO"
  );
  # https://about.gitlab.com/2019/01/31/security-release-gitlab-11-dot-7-dot-3-released/
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  # https://vuxml.freebsd.org/freebsd/467b7cbe-257d-11e9-8573-001b217b3468.html
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gitlab-ce");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/01");
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

if (pkg_test(save_report:TRUE, pkg:"gitlab-ce>=11.7.0<11.7.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gitlab-ce>=11.6.0<11.6.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gitlab-ce>=0.0.0<11.5.10")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
