#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1872-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127481);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_name(english:"Debian DLA-1872-1 : python-django security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that there were two vulnerabilities in the Django
web development framework :

  - CVE-2019-14232: Prevent a possible denial of service in
    django.utils.text.Truncator.

    If django.utils.text.Truncator's chars() and words()
    methods were passed the html=True argument, they were
    extremely slow to evaluate certain inputs due to a
    catastrophic backtracking vulnerability in a regular
    expression. The chars() and words() methods are used to
    implement the truncatechars_html and truncatewords_html
    template filters, which were thus vulnerable.

    The regular expressions used by Truncator have been
    simplified in order to avoid potential backtracking
    issues. As a consequence, trailing punctuation may now
    at times be included in the truncated output.

  - CVE-2019-14233: Prevent a possible denial of service in
    strip_tags().

    Due to the behavior of the underlying HTMLParser,
    django.utils.html.strip_tags() would be extremely slow
    to evaluate certain inputs containing large sequences of
    nested incomplete HTML entities. The strip_tags() method
    is used to implement the corresponding striptags
    template filter, which was thus also vulnerable.

    strip_tags() now avoids recursive calls to HTMLParser
    when progress removing tags, but necessarily incomplete
    HTML entities, stops being made.

    Remember that absolutely NO guarantee is provided about
    the results of strip_tags() being HTML safe. So NEVER
    mark safe the result of a strip_tags() call without
    escaping it first, for example with
    django.utils.html.escape().

For Debian 8 'Jessie', these has been fixed in python-django version
1.7.11-1+deb8u7.

We recommend that you upgrade your python-django packages. You can
find more information in upstream's announcement :

https://www.djangoproject.com/weblog/2019/aug/01/security-releases/

Thanks to Carlton Gibson et al. for their handling of these issues.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/08/msg00005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/python-django"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.djangoproject.com/weblog/2019/aug/01/security-releases/"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-django-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-django-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-django");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
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
if (deb_check(release:"8.0", prefix:"python-django", reference:"1.7.11-1+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"python-django-common", reference:"1.7.11-1+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"python-django-doc", reference:"1.7.11-1+deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"python3-django", reference:"1.7.11-1+deb8u7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
