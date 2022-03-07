include("compat.inc");


if (description)
{
  script_id(51799276);
  script_version("1.3");
  script_name(english:"uniview camera CNVD-2019-05768");
  script_summary(english:"uniview camera CNVD-2019-05768");
  script_set_attribute(attribute:"description", value:"uniview camera CNVD-2019-05768.");
  script_set_attribute(attribute:"solution", value:"None");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"risk_factor", value:"Medium");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"Camera");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  
  script_dependencies("uniview_camera_detect.nasl");
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

banner = get_kb_item("uniview_camrea");
if(isnull(banner)) exit(0);

if ("IPC232S-IR3-HF40-C-DT" >< banner){
	security_hole(port:port, data:"UniView CAMREA Find vuln CNVD-2019-05768 banner ：" + banner);	
}

exit(0);
