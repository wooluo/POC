#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4455. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125709);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/12 17:35:38");

  script_cve_id("CVE-2018-16860", "CVE-2019-12098");
  script_xref(name:"DSA", value:"4455");

  script_name(english:"Debian DSA-4455-1 : heimdal - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Heimdal, an implementation
of Kerberos 5 that aims to be compatible with MIT Kerberos.

  - CVE-2018-16860
    Isaac Boukris and Andrew Bartlett discovered that
    Heimdal was susceptible to man-in-the-middle attacks
    caused by incomplete checksum validation. Details on the
    issue can be found in the Samba advisory at
    https://www.samba.org/samba/security/CVE-2018-16860.html
    .

  - CVE-2019-12098
    It was discovered that failure of verification of the
    PA-PKINIT-KX key exchange client-side could permit to
    perform man-in-the-middle attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=928966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=929064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-16860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.samba.org/samba/security/CVE-2018-16860.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-12098"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/heimdal"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/heimdal"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4455"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the heimdal packages.

For the stable distribution (stretch), these problems have been fixed
in version 7.1.0+dfsg-13+deb9u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:heimdal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/05");
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
if (deb_check(release:"9.0", prefix:"heimdal-clients", reference:"7.1.0+dfsg-13+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"heimdal-dbg", reference:"7.1.0+dfsg-13+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"heimdal-dev", reference:"7.1.0+dfsg-13+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"heimdal-docs", reference:"7.1.0+dfsg-13+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"heimdal-kcm", reference:"7.1.0+dfsg-13+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"heimdal-kdc", reference:"7.1.0+dfsg-13+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"heimdal-multidev", reference:"7.1.0+dfsg-13+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"heimdal-servers", reference:"7.1.0+dfsg-13+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libasn1-8-heimdal", reference:"7.1.0+dfsg-13+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libgssapi3-heimdal", reference:"7.1.0+dfsg-13+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libhcrypto4-heimdal", reference:"7.1.0+dfsg-13+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libhdb9-heimdal", reference:"7.1.0+dfsg-13+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libheimbase1-heimdal", reference:"7.1.0+dfsg-13+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libheimntlm0-heimdal", reference:"7.1.0+dfsg-13+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libhx509-5-heimdal", reference:"7.1.0+dfsg-13+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libkadm5clnt7-heimdal", reference:"7.1.0+dfsg-13+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libkadm5srv8-heimdal", reference:"7.1.0+dfsg-13+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libkafs0-heimdal", reference:"7.1.0+dfsg-13+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libkdc2-heimdal", reference:"7.1.0+dfsg-13+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libkrb5-26-heimdal", reference:"7.1.0+dfsg-13+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libotp0-heimdal", reference:"7.1.0+dfsg-13+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libroken18-heimdal", reference:"7.1.0+dfsg-13+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libsl0-heimdal", reference:"7.1.0+dfsg-13+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"libwind0-heimdal", reference:"7.1.0+dfsg-13+deb9u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
