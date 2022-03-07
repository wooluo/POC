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
  script_id(127547);
  script_version("1.3");
  script_cvs_date("Date: 2019/08/20 11:58:13");

  script_cve_id("CVE-2019-14232", "CVE-2019-14233", "CVE-2019-14234", "CVE-2019-14235");

  script_name(english:"FreeBSD : Django -- multiple vulnerabilities (6e65dfea-b614-11e9-a3a2-1506e15611cc)");
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
"Django release notes :

CVE-2019-14232: Denial-of-service possibility in
django.utils.text.Truncator

If django.utils.text.Truncator's chars() and words() methods were
passed the html=True argument, they were extremely slow to evaluate
certain inputs due to a catastrophic backtracking vulnerability in a
regular expression. The chars() and words() methods are used to
implement the truncatechars_html and truncatewords_html template
filters, which were thus vulnerable

The regular expressions used by Truncator have been simplified in
order to avoid potential backtracking issues. As a consequence,
trailing punctuation may now at times be included in the truncated
output.

CVE-2019-14233: Denial-of-service possibility in strip_tags()

Due to the behavior of the underlying HTMLParser,
django.utils.html.strip_tags() would be extremely slow to evaluate
certain inputs containing large sequences of nested incomplete HTML
entities. The strip_tags() method is used to implement the
corresponding striptags template filter, which was thus also
vulnerable.

strip_tags() now avoids recursive calls to HTMLParser when progress
removing tags, but necessarily incomplete HTML entities, stops being
made.

Remember that absolutely NO guarantee is provided about the results of
strip_tags() being HTML safe. So NEVER mark safe the result of a
strip_tags() call without escaping it first, for example with
django.utils.html.escape().

CVE-2019-14234: SQL injection possibility in key and index lookups for
JSONField/HStoreField

Key and index lookups for JSONField and key lookups for HStoreField
were subject to SQL injection, using a suitably crafted dictionary,
with dictionary expansion, as the **kwargs passed to
QuerySet.filter().

CVE-2019-14235: Potential memory exhaustion in
django.utils.encoding.uri_to_iri()

If passed certain inputs, django.utils.encoding.uri_to_iri() could
lead to significant memory usage due to excessive recursion when
re-percent-encoding invalid UTF-8 octet sequences.

uri_to_iri() now avoids recursion when re-percent-encoding invalid
UTF-8 octet sequences."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.djangoproject.com/en/1.11/releases/1.11.23/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.djangoproject.com/en/2.1/releases/2.1.11/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.djangoproject.com/en/2.2/releases/2.2.4/"
  );
  # https://vuxml.freebsd.org/freebsd/6e65dfea-b614-11e9-a3a2-1506e15611cc.html
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py27-django111");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py27-django21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py27-django22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py35-django111");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py35-django21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py35-django22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py36-django111");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py36-django21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py36-django22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py37-django111");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py37-django21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py37-django22");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
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

if (pkg_test(save_report:TRUE, pkg:"py27-django111<1.11.23")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py35-django111<1.11.23")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py36-django111<1.11.23")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py37-django111<1.11.23")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py27-django21<2.1.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py35-django21<2.1.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py36-django21<2.1.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py37-django21<2.1.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py27-django22<2.2.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py35-django22<2.2.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py36-django22<2.2.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py37-django22<2.2.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
