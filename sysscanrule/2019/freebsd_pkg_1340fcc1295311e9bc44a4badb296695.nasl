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
  script_id(121604);
  script_version("1.2");
  script_cvs_date("Date: 2019/03/29  9:35:27");

  script_cve_id("CVE-2019-3814");

  script_name(english:"FreeBSD : mail/dovecot -- Suitable client certificate can be used to login as other user (1340fcc1-2953-11e9-bc44-a4badb296695)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Aki Tuomi (Open-Xchange Oy) reports :

Normally Dovecot is configured to authenticate
imap/pop3/managesieve/submission clients using regular
username/password combination. Some installations have also required
clients to present a trusted SSL certificate on top of that. It's also
possible to configure Dovecot to take the username from the
certificate instead of from the user provided authentication. It's
also possible to avoid having a password at all, only trusting the SSL
certificate.

If the provided trusted SSL certificate is missing the username field,
Dovecot should be failing the authentication. However, the earlier
versions will take the username from the user provided authentication
fields (e.g. LOGIN command). If there is no additional password
verification, this allows the attacker to login as anyone else in the
system.

This affects only installations using :

auth_ssl_require_client_cert = yes auth_ssl_username_from_cert = yes

Attacker must also have access to a valid trusted certificate without
the ssl_cert_username_field in it. The default is commonName, which
almost certainly exists in all certificates. This could happen for
example if ssl_cert_username_field is a field that normally doesn't
exist, and attacker has access to a web server's certificate (and
key), which is signed with the same CA.

Attack can be migitated by having the certificates with proper
Extended Key Usage, such as 'TLS Web Server' and 'TLS Web Server
Client'.

Also, ssl_cert_username_field setting was ignored with external SMTP
AUTH, because none of the MTAs (Postfix, Exim) currently send the
cert_username field. This may have allowed users with trusted
certificate to specify any username in the authentication. This does
not apply to Dovecot Submission service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mail-archive.com/dovecot@dovecot.org/msg76117.html"
  );
  # https://vuxml.freebsd.org/freebsd/1340fcc1-2953-11e9-bc44-a4badb296695.html
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:dovecot");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/06");
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

if (pkg_test(save_report:TRUE, pkg:"dovecot<2.3.4.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
