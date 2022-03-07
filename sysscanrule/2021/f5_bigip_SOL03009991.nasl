#
# 
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K03009991.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(147626);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/18");

  script_cve_id("CVE-2021-22986");
  script_xref(name:"IAVA", value:"2021-A-0127");

  script_name(english:"F5 Networks BIG-IP : iControl REST unauthenticated remote command execution vulnerability (K03009991)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The iControl REST interface has an unauthenticated remote command
execution vulnerability. (CVE-2021-22986)

Impact

This vulnerability allows for unauthenticated attackers with network
access to the iControl REST interface, through the BIG-IP management
interface and self IP addresses, to execute arbitrary system commands,
create or delete files, and disable services. This vulnerability can
only be exploited through the control plane and cannot be exploited
through the data plane. Exploitation can lead to complete system
compromise. The BIG-IP system in Appliance mode is also vulnerable.

Note : If you believe your system may have been compromised, refer
toK11438344: Considerations and guidance when you suspect a security
compromise on a BIG-IP system."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K03009991"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K11438344"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K03009991."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22986");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_access_policy_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_advanced_firewall_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_acceleration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_security_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_application_visibility_and_reporting");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_global_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_link_controller");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_local_traffic_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_policy_enforcement_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"F5 Networks Local Security Checks");

  script_dependencies("f5_bigip_detect.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/BIG-IP/hotfix", "Host/BIG-IP/modules", "Host/BIG-IP/version", "Settings/ParanoidReport");

  exit(0);
}


include("f5_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
version = get_kb_item("Host/BIG-IP/version");
if ( ! version ) audit(AUDIT_OS_NOT, "F5 Networks BIG-IP");
if ( isnull(get_kb_item("Host/BIG-IP/hotfix")) ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/hotfix");
if ( ! get_kb_item("Host/BIG-IP/modules") ) audit(AUDIT_KB_MISSING, "Host/BIG-IP/modules");

sol = "K03009991";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.2","14.1.0-14.1.3","13.1.0-13.1.3","12.1.0-12.1.5");
vmatrix["AFM"]["unaffected"] = make_list("16.0.1.1","15.1.2.1","14.1.4","13.1.3.6","12.1.5.3");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.2","14.1.0-14.1.3","13.1.0-13.1.3","12.1.0-12.1.5");
vmatrix["AM"]["unaffected"] = make_list("16.0.1.1","15.1.2.1","14.1.4","13.1.3.6","12.1.5.3");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.2","14.1.0-14.1.3","13.1.0-13.1.3","12.1.0-12.1.5");
vmatrix["APM"]["unaffected"] = make_list("16.0.1.1","15.1.2.1","14.1.4","13.1.3.6","12.1.5.3");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.2","14.1.0-14.1.3","13.1.0-13.1.3","12.1.0-12.1.5");
vmatrix["ASM"]["unaffected"] = make_list("16.0.1.1","15.1.2.1","14.1.4","13.1.3.6","12.1.5.3");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.2","14.1.0-14.1.3","13.1.0-13.1.3","12.1.0-12.1.5");
vmatrix["AVR"]["unaffected"] = make_list("16.0.1.1","15.1.2.1","14.1.4","13.1.3.6","12.1.5.3");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.2","14.1.0-14.1.3","13.1.0-13.1.3","12.1.0-12.1.5");
vmatrix["GTM"]["unaffected"] = make_list("16.0.1.1","15.1.2.1","14.1.4","13.1.3.6","12.1.5.3");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.2","14.1.0-14.1.3","13.1.0-13.1.3","12.1.0-12.1.5");
vmatrix["LC"]["unaffected"] = make_list("16.0.1.1","15.1.2.1","14.1.4","13.1.3.6","12.1.5.3");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.2","14.1.0-14.1.3","13.1.0-13.1.3","12.1.0-12.1.5");
vmatrix["LTM"]["unaffected"] = make_list("16.0.1.1","15.1.2.1","14.1.4","13.1.3.6","12.1.5.3");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("16.0.0-16.0.1","15.1.0-15.1.2","14.1.0-14.1.3","13.1.0-13.1.3","12.1.0-12.1.5");
vmatrix["PEM"]["unaffected"] = make_list("16.0.1.1","15.1.2.1","14.1.4","13.1.3.6","12.1.5.3");


if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  if (report_verbosity > 0) security_hole(port:0, extra:bigip_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = bigip_get_tested_modules();
  audit_extra = "For BIG-IP module(s) " + tested + ",";
  if (tested) audit(AUDIT_INST_VER_NOT_VULN, audit_extra, version);
  else audit(AUDIT_HOST_NOT, "running any of the affected modules");
}
