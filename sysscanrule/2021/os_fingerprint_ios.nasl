#
# 
#

include("compat.inc");

if (description)
{
  script_id(126588);
  script_version("1.3");
  script_cvs_date("Date: 2020/01/22");

  script_name(english:"OS Identification: iPhone or iPad");
  script_summary(english:"Determines the remote operating system");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to identify the remote device as an iOS system based on the
list of open ports");
  script_set_attribute(attribute:"description", value:
"Only port 62078 is open on the remote host. It's highly likely to be an iPhone or
an iPad.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/10");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service.nasl");
  script_require_ports(62078);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

# We want to make sure we only go ahead if 62078 is open
flag = get_kb_item_or_exit("Ports/tcp/62078");

# now make sure that's the only open port
tcp_ports = get_kb_list("Ports/tcp/*");

if (max_index(tcp_ports) > 1)
  exit(0, "Ports other than 62078 are open on the remote host");

if ( flag )
{
 set_kb_item(name:"Host/OS/iOS", value:"iPhone or iPad");
 set_kb_item(name:"Host/OS/iOS/Confidence", value:90);
 set_kb_item(name:"Host/OS/iOS/Type", value:"embedded");
}
