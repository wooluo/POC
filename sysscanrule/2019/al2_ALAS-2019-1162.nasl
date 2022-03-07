#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1162.
#

include("compat.inc");

if (description)
{
  script_id(122260);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/10 16:04:12");

  script_cve_id("CVE-2017-1000254", "CVE-2017-1000257", "CVE-2017-8816", "CVE-2017-8817", "CVE-2017-8818", "CVE-2018-16839", "CVE-2018-16840", "CVE-2018-16842", "CVE-2018-16890", "CVE-2018-20483", "CVE-2019-3822", "CVE-2019-3823");
  script_xref(name:"ALAS", value:"2019-1162");

  script_name(english:"Amazon Linux 2 : curl (ALAS-2019-1162)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libcurl is vulnerable to a heap buffer out-of-bounds read. The
function handling incoming NTLM type-2 messages
(`lib/vauth/ntlm.c:ntlm_decode_type2_target`) does not validate
incoming data correctly and is subject to an integer overflow
vulnerability. Using that overflow, a malicious or broken NTLM server
could trick libcurl to accept a bad length + offset combination that
would lead to a buffer read out-of-bounds.(CVE-2018-16890)

The NTLM authentication feature in curl and libcurl before 7.57.0 on
32-bit platforms allows attackers to cause a denial of service
(integer overflow and resultant buffer overflow, and application
crash) or possibly have unspecified other impact via vectors involving
long user and password fields.(CVE-2017-8816)

curl and libcurl before 7.57.0 on 32-bit platforms allow attackers to
cause a denial of service (out-of-bounds access and application crash)
or possibly have unspecified other impact because too little memory is
allocated for interfacing to an SSL library.(CVE-2017-8818)

libcurl may read outside of a heap allocated buffer when doing FTP.
When libcurl connects to an FTP server and successfully logs in
(anonymous or not), it asks the server for the current directory with
the `PWD` command. The server then responds with a 257 response
containing the path, inside double quotes. The returned path name is
then kept by libcurl for subsequent uses. Due to a flaw in the string
parser for this directory name, a directory name passed like this but
without a closing double quote would lead to libcurl not adding a
trailing NUL byte to the buffer holding the name. When libcurl would
then later access the string, it could read beyond the allocated heap
buffer and crash or wrongly access data beyond the buffer, thinking it
was part of the path. A malicious server could abuse this fact and
effectively prevent libcurl-based clients to work with it - the PWD
command is always issued on new FTP connections and the mistake has a
high chance of causing a segfault. The simple fact that this has issue
remained undiscovered for this long could suggest that malformed PWD
responses are rare in benign servers. We are not aware of any exploit
of this flaw. This bug was introduced in commit
[415d2e7cb7](https://github.com/curl/curl/commit/415d2e7cb7), March
2005. In libcurl version 7.56.0, the parser always zero terminates the
string but also rejects it if not terminated properly with a final
double quote.(CVE-2017-1000254)

Curl versions 7.14.1 through 7.61.1 are vulnerable to a heap-based
buffer over-read in the tool_msgs.c:voutf() function that may result
in information exposure and denial of service.(CVE-2018-16842)

libcurl is vulnerable to a stack-based buffer overflow. The function
creating an outgoing NTLM type-3 header
(`lib/vauth/ntlm.c:Curl_auth_create_ntlm_type3_message()`), generates
the request HTTP header contents based on previously received data.
The check that exists to prevent the local buffer from getting
overflowed is implemented wrongly (using unsigned math) and as such it
does not prevent the overflow from happening. This output data can
grow larger than the local buffer if very large 'nt response' data is
extracted from a previous NTLMv2 header provided by the malicious or
broken HTTP server. Such a 'large value' needs to be around 1000 bytes
or more. The actual payload data copied to the target buffer comes
from the NTLMv2 type-2 response header.(CVE-2019-3822)

libcurl is vulnerable to a heap out-of-bounds read in the code
handling the end-of-response for SMTP. If the buffer passed to
`smtp_endofresp()` isn't NUL terminated and contains no character
ending the parsed number, and `len` is set to 5, then the `strtol()`
call reads beyond the allocated buffer. The read contents will not be
returned to the caller.(CVE-2019-3823)

The FTP wildcard function in curl and libcurl before 7.57.0 allows
remote attackers to cause a denial of service (out-of-bounds read and
application crash) or possibly have unspecified other impact via a
string that ends with an '[' character.(CVE-2017-8817)

set_file_metadata in xattr.c in GNU Wget before 1.20.1 stores a file's
origin URL in the user.xdg.origin.url metadata attribute of the
extended attributes of the downloaded file, which allows local users
to obtain sensitive information (e.g., credentials contained in the
URL) by reading this attribute, as demonstrated by getfattr. This also
applies to Referer information in the user.xdg.referrer.url metadata
attribute. According to 2016-07-22 in the Wget ChangeLog,
user.xdg.origin.url was partially based on the behavior of
fwrite_xattr in tool_xattr.c in curl.(CVE-2018-20483)

A buffer overrun flaw was found in the IMAP handler of libcurl. By
tricking an unsuspecting user into connecting to a malicious IMAP
server, an attacker could exploit this flaw to potentially cause
information disclosure or crash the application.(CVE-2017-1000257)

A heap use-after-free flaw was found in curl versions from 7.59.0
through 7.61.1 in the code related to closing an easy handle. When
closing and cleaning up an 'easy' handle in the `Curl_close()`
function, the library code first frees a struct (without nulling the
pointer) and might then subsequently erroneously write to a struct
field within that already freed struct.(CVE-2018-16840)

Curl versions 7.33.0 through 7.61.1 are vulnerable to a buffer overrun
in the SASL authentication code that may lead to denial of
service.(CVE-2018-16839)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1162.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update curl' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/19");
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
if (rpm_check(release:"AL2", reference:"curl-7.61.1-9.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"curl-debuginfo-7.61.1-9.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"libcurl-7.61.1-9.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"libcurl-devel-7.61.1-9.amzn2.0.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / curl-debuginfo / libcurl / libcurl-devel");
}
