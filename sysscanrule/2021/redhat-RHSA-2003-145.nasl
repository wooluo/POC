#
# 
#
# @DEPRECATED@
#
# Disabled on 2020/04/09. Package fix no longer available for this end of life OS.

include('compat.inc');
if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12388);
 script_version("1.13");
script_cve_id("CVE-2003-0244");
			
 script_name(english:"RHSA-2003-145: kernel (deprecated)");
 script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated");
 
 script_set_attribute(attribute:"description", value:
'
The remote host is running a kernel which is vulnerable to a remote denial 
of service.  

The Linux kernel handles all the low-level functionality of the Operating
System.  This version of the kernel is vulnerable to a flaw wherein a remote
attacker can forge source IP addresses in such a way as to create a very
long routing hash chain.  An attacker, exploiting this flaw, would need
the ability to craft TCP/IP packets destined to (or through) the Linux kernel.
A successful attack would shut down the server.

The associated package for this end-of-life OS is no longer available.');
 script_set_attribute(attribute:"see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-145.html");
 script_set_attribute(attribute:"solution", value: "n/a");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/06");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");
 script_end_attributes();
 
 script_summary(english: "Check for the version of the kernel package"); 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2021 Tenable Network Security, Inc.");
 script_family(english: "Red Hat Local Security Checks"); 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}
# Deprecated.
exit(0, "The associated package for this end-of-life OS is no longer available.");

#include("rpm.inc");

if ( rpm_check( reference:"kernel-2.4.18-e.31", release:"RHEL2.1", cpu:"ia64") ) 
	security_warning(port:0, extra:rpm_report_get());

exit(0, "Host is not affected");
