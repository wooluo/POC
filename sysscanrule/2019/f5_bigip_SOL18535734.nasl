#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K18535734.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(123977);
  script_version("1.4");
  script_cvs_date("Date: 2019/07/17 16:36:41");

  script_cve_id("CVE-2019-6609");

  script_name(english:"F5 Networks BIG-IP : BIG-IP Secure Vault vulnerability (K18535734)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This vulnerability impacts only the iSeries platforms. On these
platforms, the secureKeyCapable attribute is not set, which causes the
Secure Vault feature to not use F5 hardware support to store the unit
key. Instead, the unit key is stored in plaintext on disk, as is the
case for Z100 systems. Additionally, this issue causes the unit key to
be stored in UCS files taken on these platforms. (CVE-2019-6609)

Impact

BIG-IP

The unit key on a BIG-IP iSeries platform is stored in plaintext. As a
result, the confidentiality of the unit key and master key on the
BIG-IP iSeries platform may be compromised. All other BIG-IP platforms
are not affected by this vulnerability.

Enterprise Manager, BIG-IQ Centralized Management, F5 iWorkflow,
Traffix SDC

There is no impact; these F5 products are not affected by this
vulnerability."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K18535734"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K18535734."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/a:f5:big-ip_webaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:f5:big-ip");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
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

sol = "K18535734";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("14.0.0-14.1.0.1","13.0.0-13.1.1.3","12.1.1HF2-12.1.4");
vmatrix["AFM"]["unaffected"] = make_list("15.0.0","14.1.0.2","13.1.1.4","12.1.4.1");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("14.0.0-14.1.0.1","13.0.0-13.1.1.3","12.1.1HF2-12.1.4");
vmatrix["AM"]["unaffected"] = make_list("15.0.0","14.1.0.2","13.1.1.4","12.1.4.1");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("14.0.0-14.1.0.1","13.0.0-13.1.1.3","12.1.1HF2-12.1.4");
vmatrix["APM"]["unaffected"] = make_list("15.0.0","14.1.0.2","13.1.1.4","12.1.4.1");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("14.0.0-14.1.0.1","13.0.0-13.1.1.3","12.1.1HF2-12.1.4");
vmatrix["ASM"]["unaffected"] = make_list("15.0.0","14.1.0.2","13.1.1.4","12.1.4.1");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("14.0.0-14.1.0.1","13.0.0-13.1.1.3","12.1.1HF2-12.1.4");
vmatrix["AVR"]["unaffected"] = make_list("15.0.0","14.1.0.2","13.1.1.4","12.1.4.1");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("14.0.0-14.1.0.1","13.0.0-13.1.1.3","12.1.1HF2-12.1.4");
vmatrix["GTM"]["unaffected"] = make_list("15.0.0","14.1.0.2","13.1.1.4","12.1.4.1");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("14.0.0-14.1.0.1","13.0.0-13.1.1.3","12.1.1HF2-12.1.4");
vmatrix["LC"]["unaffected"] = make_list("15.0.0","14.1.0.2","13.1.1.4","12.1.4.1");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("14.0.0-14.1.0.1","13.0.0-13.1.1.3","12.1.1HF2-12.1.4");
vmatrix["LTM"]["unaffected"] = make_list("15.0.0","14.1.0.2","13.1.1.4","12.1.4.1");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("14.0.0-14.1.0.1","13.0.0-13.1.1.3","12.1.1HF2-12.1.4");
vmatrix["PEM"]["unaffected"] = make_list("15.0.0","14.1.0.2","13.1.1.4","12.1.4.1");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("14.0.0-14.1.0.1","13.0.0-13.1.1.3","12.1.1HF2-12.1.4");
vmatrix["WAM"]["unaffected"] = make_list("15.0.0","14.1.0.2","13.1.1.4","12.1.4.1");


if (bigip_is_affected(vmatrix:vmatrix, sol:sol))
{
  if (report_verbosity > 0) security_warning(port:0, extra:bigip_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = bigip_get_tested_modules();
  audit_extra = "For BIG-IP module(s) " + tested + ",";
  if (tested) audit(AUDIT_INST_VER_NOT_VULN, audit_extra, version);
  else audit(AUDIT_HOST_NOT, "running any of the affected modules");
}
