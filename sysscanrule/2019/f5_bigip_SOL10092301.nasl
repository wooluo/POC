#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from F5 Networks BIG-IP Solution K10092301.
#
# The text description of this plugin is (C) F5 Networks.
#

include("compat.inc");

if (description)
{
  script_id(127495);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2019-6471");

  script_name(english:"F5 Networks BIG-IP : BIND vulnerability (K10092301)");
  script_summary(english:"Checks the BIG-IP version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"** RESERVED ** This candidate has been reserved by an organization or
individual that will use it when announcing a new security problem.
When the candidate has been publicized, the details for this candidate
will be provided. (CVE-2019-6471)

Impact

A remote attacker, who could cause the BIND resolver to perform
queries on a server, which responds deliberately with malformed
answers, can cause named to exit and result in a denial-of-service
(DoS) condition."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://cve.mitre.org/about/faqs.html#reserved_signify_in_cve_entry"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.f5.com/csp/article/K10092301"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to one of the non-vulnerable versions listed in the F5
Solution K10092301."
  );
  script_set_attribute(attribute:"risk_factor", value:"Medium");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
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

sol = "K10092301";
vmatrix = make_array();

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# AFM
vmatrix["AFM"] = make_array();
vmatrix["AFM"]["affected"  ] = make_list("15.0.0","14.0.0-14.1.0","13.1.0-13.1.1","12.1.0-12.1.4","11.5.2-11.6.4");
vmatrix["AFM"]["unaffected"] = make_list("15.0.1","13.1.3","12.1.5");

# AM
vmatrix["AM"] = make_array();
vmatrix["AM"]["affected"  ] = make_list("15.0.0","14.0.0-14.1.0","13.1.0-13.1.1","12.1.0-12.1.4","11.5.2-11.6.4");
vmatrix["AM"]["unaffected"] = make_list("15.0.1","13.1.3","12.1.5");

# APM
vmatrix["APM"] = make_array();
vmatrix["APM"]["affected"  ] = make_list("15.0.0","14.0.0-14.1.0","13.1.0-13.1.1","12.1.0-12.1.4","11.5.2-11.6.4");
vmatrix["APM"]["unaffected"] = make_list("15.0.1","13.1.3","12.1.5");

# ASM
vmatrix["ASM"] = make_array();
vmatrix["ASM"]["affected"  ] = make_list("15.0.0","14.0.0-14.1.0","13.1.0-13.1.1","12.1.0-12.1.4","11.5.2-11.6.4");
vmatrix["ASM"]["unaffected"] = make_list("15.0.1","13.1.3","12.1.5");

# AVR
vmatrix["AVR"] = make_array();
vmatrix["AVR"]["affected"  ] = make_list("15.0.0","14.0.0-14.1.0","13.1.0-13.1.1","12.1.0-12.1.4","11.5.2-11.6.4");
vmatrix["AVR"]["unaffected"] = make_list("15.0.1","13.1.3","12.1.5");

# GTM
vmatrix["GTM"] = make_array();
vmatrix["GTM"]["affected"  ] = make_list("15.0.0","14.0.0-14.1.0","13.1.0-13.1.1","12.1.0-12.1.4","11.5.2-11.6.4");
vmatrix["GTM"]["unaffected"] = make_list("15.0.1","13.1.3","12.1.5");

# LC
vmatrix["LC"] = make_array();
vmatrix["LC"]["affected"  ] = make_list("15.0.0","14.0.0-14.1.0","13.1.0-13.1.1","12.1.0-12.1.4","11.5.2-11.6.4");
vmatrix["LC"]["unaffected"] = make_list("15.0.1","13.1.3","12.1.5");

# LTM
vmatrix["LTM"] = make_array();
vmatrix["LTM"]["affected"  ] = make_list("15.0.0","14.0.0-14.1.0","13.1.0-13.1.1","12.1.0-12.1.4","11.5.2-11.6.4");
vmatrix["LTM"]["unaffected"] = make_list("15.0.1","13.1.3","12.1.5");

# PEM
vmatrix["PEM"] = make_array();
vmatrix["PEM"]["affected"  ] = make_list("15.0.0","14.0.0-14.1.0","13.1.0-13.1.1","12.1.0-12.1.4","11.5.2-11.6.4");
vmatrix["PEM"]["unaffected"] = make_list("15.0.1","13.1.3","12.1.5");

# WAM
vmatrix["WAM"] = make_array();
vmatrix["WAM"]["affected"  ] = make_list("15.0.0","14.0.0-14.1.0","13.1.0-13.1.1","12.1.0-12.1.4","11.5.2-11.6.4");
vmatrix["WAM"]["unaffected"] = make_list("15.0.1","13.1.3","12.1.5");


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
