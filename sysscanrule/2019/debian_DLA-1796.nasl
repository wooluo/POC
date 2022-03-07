#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1796-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125297);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/21  9:43:49");

  script_cve_id("CVE-2018-1000074", "CVE-2018-1000075", "CVE-2018-1000076", "CVE-2018-1000077", "CVE-2018-1000078", "CVE-2019-8321", "CVE-2019-8322", "CVE-2019-8323", "CVE-2019-8324", "CVE-2019-8325");

  script_name(english:"Debian DLA-1796-1 : jruby security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in jruby, Java
implementation of the Ruby programming language.

CVE-2018-1000074

Deserialization of Untrusted Data vulnerability in owner command that
can result in code execution. This attack appear to be exploitable via
victim must run the `gem owner` command on a gem with a specially
crafted YAML file

CVE-2018-1000075

an infinite loop caused by negative size vulnerability in ruby gem
package tar header that can result in a negative size could cause an
infinite loop

CVE-2018-1000076

Improper Verification of Cryptographic Signature vulnerability in
package.rb that can result in a mis-signed gem could be installed, as
the tarball would contain multiple gem signatures.

CVE-2018-1000077

Improper Input Validation vulnerability in ruby gems specification
homepage attribute that can result in a malicious gem could set an
invalid homepage URL

CVE-2018-1000078

Cross Site Scripting (XSS) vulnerability in gem server display of
homepage attribute that can result in XSS. This attack appear to be
exploitable via the victim must browse to a malicious gem on a
vulnerable gem server

CVE-2019-8321

Gem::UserInteraction#verbose calls say without escaping, escape
sequence injection is possible

CVE-2019-8322

The gem owner command outputs the contents of the API response
directly to stdout. Therefore, if the response is crafted, escape
sequence injection may occur

CVE-2019-8323

Gem::GemcutterUtilities#with_response may output the API response to
stdout as it is. Therefore, if the API side modifies the response,
escape sequence injection may occur.

CVE-2019-8324

A crafted gem with a multi-line name is not handled correctly.
Therefore, an attacker could inject arbitrary code to the stub line of
gemspec

CVE-2019-8325

Gem::CommandManager#run calls alert_error without escaping, escape
sequence injection is possible. (There are many ways to cause an
error.)

For Debian 8 'Jessie', these problems have been fixed in version
1.5.6-9+deb8u1.

We recommend that you upgrade your jruby packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/05/msg00028.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/jruby"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected jruby package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jruby");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"8.0", prefix:"jruby", reference:"1.5.6-9+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
