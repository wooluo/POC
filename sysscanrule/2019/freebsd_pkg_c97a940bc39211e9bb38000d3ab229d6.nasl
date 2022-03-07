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
  script_id(128043);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/22 12:32:34");

  script_cve_id("CVE-2019-9511", "CVE-2019-9512", "CVE-2019-9513", "CVE-2019-9514", "CVE-2019-9515", "CVE-2019-9516", "CVE-2019-9517", "CVE-2019-9518");

  script_name(english:"FreeBSD : Node.js -- multiple vulnerabilities (c97a940b-c392-11e9-bb38-000d3ab229d6) (0-Length Headers Leak) (Data Dribble) (Empty Frames Flood) (Internal Data Buffering) (Ping Flood) (Reset Flood) (Resource Loop) (Settings Flood)");
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

Node.js, as well as many other implementations of HTTP/2, have been
found vulnerable to Denial of Service attacks. See
https://github.com/Netflix/security-bulletins/blob/master/advisories/t
hird-party/2019-002.md for more information.

Updates are now available for all active Node.js release lines,
including Linux ARMv6 builds for Node.js 8.x (which had been delayed).

We recommend that all Node.js users upgrade to a version listed below
as soon as possible. Vulnerabilities Fixed Impact: All versions of
Node.js 8 (LTS 'Carbon'), Node.js 10 (LTS 'Dubnium'), and Node.js 12
(Current) are vulnerable to the following :

- CVE-2019-9511 'Data Dribble': The attacker requests a large amount
of data from a specified resource over multiple streams. They
manipulate window size and stream priority to force the server to
queue the data in 1-byte chunks. Depending on how efficiently this
data is queued, this can consume excess CPU, memory, or both,
potentially leading to a denial of service.

- CVE-2019-9512 'Ping Flood': The attacker sends continual pings to an
HTTP/2 peer, causing the peer to build an internal queue of responses.
Depending on how efficiently this data is queued, this can consume
excess CPU, memory, or both, potentially leading to a denial of
service.

- CVE-2019-9513 'Resource Loop': The attacker creates multiple request
streams and continually shuffles the priority of the streams in a way
that causes substantial churn to the priority tree. This can consume
excess CPU, potentially leading to a denial of service.

- CVE-2019-9514 'Reset Flood': The attacker opens a number of streams
and sends an invalid request over each stream that should solicit a
stream of RST_STREAM frames from the peer. Depending on how the peer
queues the RST_STREAM frames, this can consume excess memory, CPU, or
both, potentially leading to a denial of service.

- CVE-2019-9515 'Settings Flood': The attacker sends a stream of
SETTINGS frames to the peer. Since the RFC requires that the peer
reply with one acknowledgement per SETTINGS frame, an empty SETTINGS
frame is almost equivalent in behavior to a ping. Depending on how
efficiently this data is queued, this can consume excess CPU, memory,
or both, potentially leading to a denial of service.

- CVE-2019-9516 '0-Length Headers Leak': The attacker sends a stream
of headers with a 0-length header name and 0-length header value,
optionally Huffman encoded into 1-byte or greater headers. Some
implementations allocate memory for these headers and keep the
allocation alive until the session dies. This can consume excess
memory, potentially leading to a denial of service.

- CVE-2019-9517 'Internal Data Buffering': The attacker opens the
HTTP/2 window so the peer can send without constraint; however, they
leave the TCP window closed so the peer cannot actually write (many
of) the bytes on the wire. The attacker then sends a stream of
requests for a large response object. Depending on how the servers
queue the responses, this can consume excess memory, CPU, or both,
potentially leading to a denial of service.

- CVE-2019-9518 'Empty Frames Flood': The attacker sends a stream of
frames with an empty payload and without the end-of-stream flag. These
frames can be DATA, HEADERS, CONTINUATION and/or PUSH_PROMISE. The
peer spends time processing each frame disproportionate to attack
bandwidth. This can consume excess CPU, potentially leading to a
denial of service. (Discovered by Piotr Sikora of Google)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://nodejs.org/en/blog/vulnerability/aug-2019-security-releases/"
  );
  # https://vuxml.freebsd.org/freebsd/c97a940b-c392-11e9-bb38-000d3ab229d6.html
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/21");
  script_set_attribute(attribute:"in_the_news", value:"true");
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

if (pkg_test(save_report:TRUE, pkg:"node<12.8.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node10<10.16.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node8<8.16.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
