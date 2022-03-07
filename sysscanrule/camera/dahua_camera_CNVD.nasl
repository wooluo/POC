include("compat.inc");


if (description)
{
  script_id(51799277);
  script_cve_id("CVE-2020-9500","CVE-2020-9499","CVE-2020-9502","CVE-2019-9682");
  script_version("1.3");
  script_name(english:"uniview camera  CNVD-2020-22979\CNVD-2020-22980");
  script_summary(english:"uniview camera CNVD-2020-22979\CNVD-2020-22980");
  script_set_attribute(attribute:"description", value:"uniview camera CNVD-2020-22979\CNVD-2020-22980.");
  script_set_attribute(attribute:"solution", value:"None");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"Camera");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  
  script_dependencies("dahua_camera_detect.nasl");
  script_require_ports("Services/www", 80, 443);
  exit(0);
}


############################################
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("json.inc");
include("openvas-https2.inc");

version = get_kb_item("Dahua_camrea");
if(isnull(version)) exit(0);

if (("NVR5" >< version || "NVR4" >< version) && "4KS2" >!< version){
	security_hole(port:port, data:"UniView CAMREA Find Vuln version ：" + version);	
}


# IPC-HDBW1320E-W   "CVE-2020-9502","CVE-2019-9682"
if ("IPC-HDBW1320E-W" >< version){
	security_hole(port:port, data:"UniView CAMREA Find Vuln version ：" + version);	
}

#  IPC-HX5842H   IPC-HX7842H 
find = egrep(pattern:".*IPC-H.[57]842H.*", string:version);
if(find){
	security_hole(port:port, data:"UniView CAMREA Find Vuln version ：" + version);	
}

#IPC-HXXX5X4X

find2 = egrep(pattern:".*IPC-H...5.4.*", string:version);
find2_1 = egrep(pattern:".*IPC-H.5.*", string:version);
if(find2_1) exit(0);
if(find2){
	security_hole(port:port, data:"UniView CAMREA Find Vuln version ：" + version);	
}

#  IPC-HX2XXX Series 

find3 = egrep(pattern:".*IPC-H.2.*", string:version);
find3_1 = egrep(pattern:".*IPC-H.2[58].*", string:version);
if(find3_1) exit(0);
if(find3){
	security_hole(port:port, data:"UniView CAMREA Find Vuln version ：" + version);	
}


if ("SD6AL" >< version || "SD5A" >< version || "SD1A" >< version || "PTZ1A" >< version || "SD50" >< version || "SD52C"  >< version ){
	security_hole(port:port, data:"UniView CAMREA Find Vuln version ：" + version);	
}

exit(0);
