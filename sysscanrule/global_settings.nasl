include("compat.inc");

if (description)
{
 script_id(12288);
 script_version("1.38");
 script_set_attribute(attribute:"plugin_modification_date", value:"2015/12/16");

 script_name(english:"Global variable settings");
 script_summary(english:"Global variable settings.");

 script_set_attribute(attribute:"synopsis", value:
"Sets global settings.");
 script_set_attribute(attribute:"description", value:
"This plugin configures miscellaneous global variables for GizaNE
plugins. It does not perform any security checks but may disable or
change the behavior of others.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/06/29");

 script_set_attribute(attribute:"plugin_type", value:"settings");
 script_set_attribute(attribute:"agent", value:"all");
 script_end_attributes();

 script_category(ACT_SETTINGS);

 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_family(english:"Settings");

 if ( NASL_LEVEL >= 3200 )
   script_add_preference(name:"Probe services on every port", type:"checkbox", value:"yes");
 script_add_preference(name:"Do not log in with user accounts not specified in the policy", type:"checkbox", value:"no");
 if ( NASL_LEVEL >= 4000 )
  script_add_preference(name:"Enable CGI scanning", type:"checkbox", value:"no");
 else
  script_add_preference(name:"Enable CGI scanning", type:"checkbox", value:"yes");

 script_add_preference(name:"Network type", type:"radio", value:"Mixed (use RFC 1918);Private LAN;Public WAN (Internet)");
 script_add_preference(name:"Enable experimental scripts", type:"checkbox", value:"no");
 script_add_preference(name:"Thorough tests (slow)", type:"checkbox", value:"no");
 script_add_preference(name:"Report verbosity", type:"radio", value:"Normal;Quiet;Verbose");
 script_add_preference(name:"Report paranoia", type:"radio", value:"Normal;Avoid false alarms;Paranoid (more false alarms)");
 script_add_preference(name:"HTTP User-Agent", type:"entry", value:"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)");
 script_add_preference(name:"SSL certificate to use : ", type:"file", value:"");
 script_add_preference(name:"SSL CA to trust : ", type:"file", value:"");
 script_add_preference(name:"SSL key to use : ", type:"file", value:"");
 script_add_preference(name:"SSL password for SSL key : ", type:"password", value:"");
 script_add_preference(name:"Enumerate all SSL ciphers", type:"checkbox", value:"yes");
 script_add_preference(name:"Enable CRL checking (connects to Internet)", type:"checkbox", value:"no");
 script_add_preference(name:"Enable plugin debugging", type:"checkbox", value:"no");

 exit(0);
}

if ( get_kb_item("global_settings/disable_service_discovery")  ) exit(0);
if ( script_get_preference("SSL certificate to use : ") )
 cert = script_get_preference_file_location("SSL certificate to use : ");

if ( script_get_preference("SSL CA to trust : ") )
 ca = script_get_preference_file_location("SSL CA to trust : ");

ciph = script_get_preference("Enumerate all SSL ciphers");
if ( ciph == "no" ) set_kb_item(name:"global_settings/disable_ssl_cipher_neg", value:TRUE);

if ( script_get_preference("SSL key to use : ") )
 key = script_get_preference_file_location("SSL key to use : ");

pass = script_get_preference("SSL password for SSL key : ");

if ( cert && key )
{
 if ( NASL_LEVEL >= 5000 )
 {
  mutex_lock("global_settings_convert");
  if ( get_global_kb_item("/tmp/global_settings_convert") == NULL )
  {
   if ( file_stat(cert) )
   {
    b = fread(cert);
    unlink(cert);
    fwrite(data:b, file:cert);
   }

   if ( file_stat(key) )
   {
    b = fread(key);
    unlink(key);
    fwrite(data:b, file:key);
   }

   if ( !isnull(ca) && file_stat(ca) )
   {
    b = fread(ca);
    unlink(ca);
    fwrite(data:b, file:ca);
   }
   set_global_kb_item(name:"/tmp/global_settings_convert", value:TRUE);
  }
  mutex_unlock("global_settings_convert");
 }

 set_kb_item(name:"SSL/cert", value:cert);
 set_kb_item(name:"SSL/key", value:key);
 if ( !isnull(ca) ) set_kb_item(name:"SSL/CA", value:ca);
 if ( !isnull(pass) ) set_kb_item(name:"SSL/password", value:pass);
}

opt = script_get_preference("Enable CRL checking (connects to Internet)");
if ( opt && opt == "yes" ) set_global_kb_item(name:"global_settings/enable_crl_checking", value:TRUE);

opt = script_get_preference("Enable plugin debugging");
if ( opt && opt == "yes" ) set_kb_item(name:"global_settings/enable_plugin_debugging", value:TRUE);

opt = script_get_preference("Probe services on every port");
if ( opt && opt == "no" ) set_kb_item(name:"global_settings/disable_service_discovery", value:TRUE);

opt = script_get_preference("Do not log in with user accounts not specified in the policy");
if ( opt && opt == "yes" ) set_kb_item(name:"global_settings/supplied_logins_only", value:TRUE);
else set_kb_item(name:"Settings/test_all_accounts", value: TRUE);

opt = script_get_preference("Enable CGI scanning");
if ( opt == "no" ) set_kb_item(name:"Settings/disable_cgi_scanning", value:TRUE);

opt = script_get_preference("Enable experimental scripts");
if (! opt || ";" >< opt ) opt = "no";
set_kb_item(name:"global_settings/experimental_scripts", value:opt);
if ( opt == "yes" ) set_kb_item(name:"Settings/ExperimentalScripts", value:TRUE);

opt = script_get_preference("Thorough tests (slow)");
if (! opt || ";" >< opt ) opt = "no";
set_kb_item(name:"global_settings/thorough_tests", value:opt);

if ( opt == "yes" ) set_kb_item(name:"Settings/ThoroughTests", value:TRUE);

opt = script_get_preference("Report verbosity");
if (! opt || ";" >< opt ) opt = "Normal";
set_kb_item(name:"global_settings/report_verbosity", value:opt);

opt = script_get_preference("Debug level");
if (! opt || ";" >< opt ) opt = "0";
set_kb_item(name:"global_settings/debug_level", value:int(opt));

opt = script_get_preference("Report paranoia");
if (! opt || ";" >< opt ) opt = "Normal";
set_kb_item(name:"global_settings/report_paranoia", value:opt);
if (opt == "Paranoid (more false alarms)")
  set_kb_item(name:"Settings/ParanoidReport", value: TRUE);

opt = script_get_preference("Network type");
if (! opt || ";" >< opt ) opt = "Mixed (RFC 1918)";
set_kb_item(name:"global_settings/network_type", value:opt);

opt = script_get_preference("HTTP User-Agent");
if (opt) {
	if(!strstr(opt, '```') && !strstr(opt, '=')) {
		set_kb_item(name:"global_settings/http_user_agent", value:opt);
	} else {
		kvs = split(opt, sep:'```', keep:0);
		foreach kv (kvs) {
			segs = split(kv, sep:'=', keep:0);
			if (len(segs) == 2) set_kb_item(name:"global_settings/"+segs[0], value:segs[1]);
		}
	}
}
http_user_agent = get_kb_item("global_settings/http_user_agent");
if(!http_user_agent) {
	http_user_agent="Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)";
	set_kb_item(name:"global_settings/http_user_agent", value:http_user_agent);
}
if ( NASL_LEVEL >= 3000 )	# http_ids_evasion.nasl is disabled
  set_kb_item(name:"http/user-agent", value:http_user_agent);

opt = script_get_preference("Host tagging");
if (! opt || ";" >< opt ) opt = "no";
set_kb_item(name:"global_settings/host_tagging", value:opt);
if ( opt == "yes" ) set_kb_item(name:"Settings/HostTagging", value:TRUE);
