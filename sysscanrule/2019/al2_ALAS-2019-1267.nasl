#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1267.
#

include("compat.inc");

if (description)
{
  script_id(127467);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2019-11709", "CVE-2019-11711", "CVE-2019-11713", "CVE-2019-11715", "CVE-2019-11717", "CVE-2019-11730", "CVE-2019-9811");
  script_xref(name:"ALAS", value:"2019-1267");

  script_name(english:"Amazon Linux 2 : thunderbird (ALAS-2019-1267)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"When an inner window is reused, it does not consider the use of
document.domain for cross-origin protections. If pages on different
subdomains ever cooperatively use document.domain, then either page
can abuse this to inject script into arbitrary pages on the other
subdomain, even those that did not use document.domain to relax their
origin security. This vulnerability affects Firefox ESR, Firefox, and
Thunderbird. (CVE-2019-11711)

Mozilla developers and community members reported memory safety bugs
present in Firefox and Firefox ESR. Some of these bugs showed evidence
of memory corruption and we presume that with enough effort that some
of these could be exploited to run arbitrary code. This vulnerability
affects Firefox ESR and Thunderbird. (CVE-2019-11709)

A vulnerability exists where the caret ('^') character is improperly
escaped constructing some URIs due to it being used as a separator,
allowing for possible spoofing of origin attributes. This
vulnerability affects Firefox ESR, Firefox, and Thunderbird.
(CVE-2019-11717)

As part of a winning Pwn2Own entry, a researcher demonstrated a
sandbox escape by installing a malicious language pack and then
opening a browser feature that used the compromised translation. This
vulnerability affects Firefox ESR, Firefox, and Thunderbird.
(CVE-2019-9811)

A use-after-free vulnerability can occur in HTTP/2 when a cached
HTTP/2 stream is closed while still in use, resulting in a potentially
exploitable crash. This vulnerability affects Firefox ESR, Firefox,
and Thunderbird. (CVE-2019-11713)

A vulnerability exists where if a user opens a locally saved HTML
file, this file can use file: URIs to access other files in the same
directory or sub-directories if the names are known or guessed. The
Fetch API can then be used to read the contents of any files stored in
these directories and they may uploaded to a server. It was
demonstrated that in combination with a popular Android messaging app,
if a malicious HTML attachment is sent to a user and they opened that
attachment in Firefox, due to that app's predictable pattern for
locally-saved file names, it is possible to read attachments the
victim received from other correspondents. This vulnerability affects
Firefox ESR, Firefox, and Thunderbird. (CVE-2019-11730)

Due to an error while parsing page content, it is possible for
properly sanitized user input to be misinterpreted and lead to XSS
hazards on websites in certain circumstances. This vulnerability
affects Firefox, Firefox, and Thunderbird. (CVE-2019-11715)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1267.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update thunderbird' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"thunderbird-60.8.0-1.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", cpu:"x86_64", reference:"thunderbird-debuginfo-60.8.0-1.amzn2.0.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird / thunderbird-debuginfo");
}
