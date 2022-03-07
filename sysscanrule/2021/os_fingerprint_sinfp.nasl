#
# (C) Tenable, Inc.
#
# SinFP is a fingerprinting tool written by GomoR and available
# at http://www.gomor.org/cgi-bin/sinfp.pl
#
# This plugin is a white-room reimplementation of the SinFP methodology
#

include("compat.inc");

if (description)
{
  script_id(25250);
  script_version("1.58");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/28");

  script_name(english:"OS Identification : SinFP");
  script_summary(english:"Determines the remote operating system");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to identify the remote operating system using the SinFP
technique.");
  script_set_attribute(attribute:"description", value:
"This script attempts to identify the operating system type and version
by using the same technique as SinFP.");
  script_set_attribute(attribute:"see_also", value:"https://link.springer.com/article/10.1007/s11416-008-0107-z");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2007-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"General");

  script_dependencies("nessus_product_setup.nasl");
  script_exclude_keys("GizaNE/product/local");

  exit(0);
}

function nasl_get_host_open_port()
{
 local_var list;
 local_var item;
 local_var open21, open25, open80, open139, open445;
 local_var candidates;
 local_var ret;

 #
 # XXX get_host_open_port() avoids a few ports, but not port 25.
 #
 ret = get_host_open_port();
 if ( ret != 25 ) return ret;

 list = get_kb_list("Ports/tcp/*");
 candidates = make_list();
 foreach item ( keys(list) )
 {
   ret = int(item - "Ports/tcp/");
   if ( ret == 21 ) open21 = TRUE;
   else if ( ret == 25 ) open25 = TRUE;
   else if ( ret == 80 ) open80 = TRUE;
   else if ( ret == 139 ) open139 = TRUE;
   else if ( ret == 445 ) open445 = TRUE;
   else candidates = make_list(candidates, ret);
 }

 if ( max_index(candidates) > 0 )
	return candidates[rand() % max_index(candidates)];
 else if ( open21 ) return 21;
 else if ( open25 ) return 25;
 else if ( open80 ) return 80;
 else if ( open139 ) return 139;
 else if ( open445 ) return 445;
 return NULL;
}

include("audit.inc");
include("raw.inc");
include("sinfp.inc");
include("global_settings.inc");

if (!defined_func("bsd_byte_ordering")) exit(0, "The NASL function 'bsd_byte_ordering()' is not defined.");
if (TARGET_IS_IPV6) audit(AUDIT_ONLY_IPV4);
if (islocalhost() && get_kb_item("GizaNE/product/local"))
  audit(AUDIT_LOCALHOST);

port = nasl_get_host_open_port();
if (!port) exit(0, "Failed to find an open port.");

res = sinfp(dport:port);
if (isnull(res)) audit(AUDIT_FN_FAIL, 'sinfp');

fingerprint = res["fingerprint"];
osname = res["osname"];
confidence = res["confidence"];

if (report_paranoia == 0 && confidence < 70) exit(0, "The degree of confidence in the fingerprint is too low.");

if ( !isnull(osname) )
{
 data = os_name_split(osname);
 if ( data["num"] > 5 ) exit(0);
 set_kb_item(name:"Host/OS/SinFP", value:data["os"]);
 if ( data["type"] )
  set_kb_item(name:"Host/OS/SinFP/Type", value:data["type"]);
 if ( data["num"] > 1 ) confidence -= 11;
 if ( data["os"] == 'Citrix NetScaler' ) confidence += 10;
 set_kb_item(name:"Host/OS/SinFP/Confidence", value:confidence);
}
  
