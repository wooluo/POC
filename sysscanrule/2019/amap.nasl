#TRUSTED 779301b5c82934c5e16bfb998715e4f0a1b7f1a33416670dc5b7895957a292337b236684c8d0046f7b606e5680829fb673caa6381d770c7242974b375fc378f2f1e1e31eec0b1ac73ba0c494c45fbc3c2e9745b74c8fec98562ea6af5298206ec2ee4490b5f95cc60ada03330bcc444ca269b65b97699d4ed5c9c70c5d7137df6dc7cb2d6b7ecc67585f47b3dafbb08f515996293f8f74c6df8bd99cf1ee00aac53c970ff00a88285eccad4efb8177dd4e529f2fe089b5606d7dc8c046788c905568dccc4d45d9daa5971f9ea009c8d8ab6442011b0a538fe43de28343d75049d1698cbff25abd2974a698e940e1426d9a32d79bbcacdfe7ecbab1293954298cb892abb261748625c7100357b9d99be468b64bc8aac20d692ab6d7d20d259e9486c2d9f218667f827adb73991ee65077cf8982378e6ce23c27ca982df671144e4c4c61dbd6e88fd298dd535e1108f6a4fdd2e86ca2a8c7ed72410ff741a9b4e952602ca73d60caa2978bb05420778967adabe9e794d2593fb6e221f7d679e6c6e5c1b79b32b6a3bb09703e33fe0fa61245a55e66dcf7200fbc814e43b26f7bc281cb7dee6f87aab619811c9589c2f1c798515c3be6f6b27389413c01726de5644be56e247d74df8e726417caadeec5de7c90952f51d1f4ddc091f5107c3363416a7365f6254a30cf20de8a215cd27f8e645161bcef488403e1cbbb1fff599be9
#
# (C) WebRAY Network Security, Inc.
#


if ( ! defined_func("pread") || ! defined_func("fread") ||
     ! defined_func("get_preference") ) exit(0);
if ( ! find_in_path("amap") ) exit(0);


include("compat.inc");


if(description)
{
 script_id(14663);
 script_version ("1.30");
 script_set_attribute(attribute:"plugin_modification_date", value:"2019/06/17");

 script_name(english: "amap (NASL wrapper)");
 script_summary(english: "Performs portscan / RPC scan / application recognition"); 

 script_set_attribute(
  attribute:"synopsis",
  value:"This plugin performs application protocol detection."
 );
 script_set_attribute(
  attribute:"description",
  value:
"This plugin runs amap to find open ports and identify applications on
the remote host. 

See the section 'plugins options' to configure it."
 );
 script_set_attribute(attribute:"see_also", value:"http://www.thc.org/thc-amap/");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/03");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_SCANNER);
 
 script_copyright(english:"This script is Copyright (C) 2004-2019 WebRAY Network Security, Inc.");
 script_family(english: "Port scanners");

 if (NASL_LEVEL >= 3210)
  script_dependencies("portscanners_stub.nasl", "portscanners_settings.nasl");
 else
  script_dependencies("ping_host.nasl", "portscanners_settings.nasl");

 if (NASL_LEVEL < 2181) exit(0);	# Cannot run

 script_add_preference(name: "File containing machine readable results : ", value: "", type: "file");

 script_add_preference(name:"Mode", type:"radio", value: "Map applications;Just grab banners;Port scan only");
 script_add_preference(name:"Quicker", type:"checkbox", value: "no");
 script_add_preference(name:"UDP scan (disabled in safe_checks)", type:"checkbox", value: "no");
 script_add_preference(name:"SSL (disabled in safe_checks)", type:"checkbox", value: "yes");
 script_add_preference(name:"RPC (disabled in safe_checks)", type:"checkbox", value: "yes");

 script_add_preference(name:"Parallel  tasks", type:"entry", value: "");
 script_add_preference(name:"Connection retries", type:"entry", value: "");
 script_add_preference(name:"Connection timeout", type:"entry", value: "");
 script_add_preference(name:"Read timeout", type:"entry", value: "");

 exit(0);
}

if (NASL_LEVEL < 2181 || ! defined_func("pread") || ! defined_func("get_preference"))
{
  set_kb_item(name: "/tmp/UnableToRun/14663", value: TRUE);
  display("Script #14663 (amap_wrapper) cannot run - upgrade libnasl\n");
  exit(0);
}

global_var tmpnam;

function do_exit()
{
  if (tmpnam) unlink(tmpnam);
}

ip = get_host_ip();
esc_ip = ""; l = strlen(ip);
for (i = 0; i < l; i ++) 
  if (ip[i] == '.')
    esc_ip = strcat(esc_ip, "\.");
  else
    esc_ip = strcat(esc_ip, ip[i]);

res = script_get_preference_file_content("File containing machine readable results : ");
if (res)
  res = egrep(pattern: "^" + esc_ip + ":[0-9]+:", string: res);
if (! res)
{
  # No result, launch amap
  if (get_kb_item("PortscannersSettings/run_only_if_needed")
      && get_kb_item("Host/full_scan")) exit(0);

tmpdir = get_tmp_dir();
if ( ! tmpdir ) do_exit();
tmpnam = strcat(tmpdir, "/amap-", get_host_ip(), "-", rand());

p = script_get_preference("UDP scan (disabled in safe_checks)");
if ("yes" >< p)
 udp_n = 1;
else
 udp_n = 0;

n_ports = 0;

for (udp_flag = 0; udp_flag <= udp_n; udp_flag ++)
{
 i = 0;
 argv[i++] = "amap";
 argv[i++] = "-q";
 argv[i++] = "-U";
 argv[i++] = "-o";
 argv[i++] = tmpnam;
 argv[i++] = "-m";
 if (udp_flag) argv[i++] = "-u";

 p = script_get_preference("Mode");
 if ("Just grab banners" >< p) argv[i++] = '-B';
 else if ("Port scan only" >< p) argv[i++] = '-P';
 else argv[i++] = '-A';

 # As all UDP probes are declared harmful, -u is incompatible with -H
 # Amap exits immediatly with a strange error.
 # I let it run just in case some "harmless" probes are added in a 
 # future version

 if (safe_checks()) argv[i++] = "-H";

 p = script_get_preference("Quicker");
 if ("yes" >< p) argv[i++] = "-1";

 # SSL and RPC probes are "harmful" and will not run if -H is set

 p = script_get_preference("SSL (disabled in safe_checks)");
 if ("no" >< p) argv[i++] = "-S";
 p = script_get_preference("RPC (disabled in safe_checks)");
 if ("no" >< p) argv[i++] = "-R";

 p = script_get_preference("Parallel  tasks"); p = int(p);
 if (p > 0) { argv[i++] = '-c'; argv[i++] = p; }
 p = script_get_preference("Connection retries"); p = int(p);
 if (p > 0) { argv[i++] = '-C'; argv[i++] = p; }
 p = script_get_preference("Connection timeout"); p = int(p);
 if (p > 0) { argv[i++] = '-T'; argv[i++] = p; }
 p = script_get_preference("Read timeout"); p = int(p);
 if (p > 0) { argv[i++] = '-t'; argv[i++] = p; }

 argv[i++] = ip;
 pr = get_preference("port_range");
 if (! pr) pr = "1-65535";
 foreach p (split(pr, sep: ',')) argv[i++] = p;

 res1 = pread(cmd: "amap", argv: argv, cd: 1, nice: 5);
 res += fread(tmpnam);
 }
}

# IP_ADDRESS:PORT:PROTOCOL:PORT_STATUS:SSL:IDENTIFICATION:PRINTABLE_BANNER:FULL_BANNER

foreach line(split(res))
{
  v = eregmatch(string: line, pattern: '^'+esc_ip+':([0-9]+):([^:]*):([a-z]+):([^:]*):([^:]*):([^:]*):(.*)$');
  if (! isnull(v) && v[3] == "open")
  {
   scanner_status(current: ++ n_ports, total: 65535 * 2);
   proto = v[2];
   port = int(v[1]); ps = strcat(proto, ':', port);
   scanner_add_port(proto: proto, port: port);
   # As amap sometimes give several results on a same port, we save 
   # the outputs and remember the last one for every port
   # The arrays use a string index to save memory
   amap_ident[ps] = v[5];
   amap_ssl[ps] = v[4];
   amap_print_banner[ps] = v[6];
   amap_full_banner[ps] = v[7];

  }
}

if (n_ports != 0)
{
 set_kb_item(name: "Host/scanned", value: TRUE);
 set_kb_item(name: 'Host/scanners/amap', value: TRUE);
 if (pr == '1-65535')
   set_kb_item(name: "Host/full_scan", value: TRUE);
}

if (udp_n && n_ports)
  set_kb_item(name: "Host/udp_scanned", value: 1);

scanner_status(current: 65535 * 2, total: 65535 * 2);

function cvtbanner(b)
{
  local_var i, l, x;
  l = strlen(b);

  if (b[0] == '0' && b[1] == 'x')
   return hex2raw(s: substr(b, 2));

  x = "";
  for (i = 0; i < l; i ++)
   if (b[i] != '\\')
    x += b[i];
   else
   {
    i++;
    if (b[i] == 'n') x += '\n';
    else if (b[i] == 'r') x += '\n';
    else if (b[i] == 't') x += '\t';
    else if (b[i] == 'f') x += '\f';
    else if (b[i] == 'v') x += '\v';
    else if (b[i] == '\\') x += '\\';
    else display('cvtbanner: unhandled escape string \\'+b[i]+'\n');
   }
  return x;
}

if (! isnull(amap_ident))
 foreach p (keys(amap_ident))
 {
  v = split(p, sep: ':', keep: 0);
  proto = v[0]; port = int(v[1]);
  if (proto == "tcp")
  {
   soc = open_sock_tcp(port);
   if (soc)
    close(soc);
   else
    security_hole(port: port, extra: "Either this port is dynamically allocated or amap killed this service.");

  }
  id = amap_ident[p];
  if (id && id != "unidentified" && id != 'ssl')
  {
   security_note(port: port, proto: proto, extra: "Amap has identified this service as " + id);
   set_kb_item(name: "Amap/"+proto+"/"+port+"/Svc", value: id);
  }

  banner = cvtbanner(b: amap_print_banner[p]);
  set_kb_item(name: "Amap/"+proto+"/"+port+"/PrintableBanner", value: banner);

  banner = cvtbanner(b: amap_full_banner[p]);
  set_kb_item(name: "Amap/"+proto+"/"+port+"/FullBanner", value: banner);
 }


do_exit();
