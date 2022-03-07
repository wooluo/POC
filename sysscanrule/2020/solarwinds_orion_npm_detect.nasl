#
# 
#

include("compat.inc");

if (description)
{
  script_id(62117);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/26");

  script_xref(name:"IAVT", value:"0001-T-0891");

  script_name(english:"SolarWinds Orion Product Detection");
  script_summary(english:"Attempts to retrieve the SolarWinds Orion login page.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a network monitoring or management
web application.");
  script_set_attribute(attribute:"description", value:
"A SolarWinds Orion product is running on the remote web server. Orion
is a core component of several network monitoring and management
applications.");
  script_set_attribute(attribute:"see_also", value:"https://www.solarwinds.com/network-performance-monitor");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_platform");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_network_performance_monitor");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_netflow_traffic_analyzer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_network_configuration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_ip_address_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_user_device_tracker");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_voip_%26_network_quality_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_server_and_application_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_web_performance_monitor");

  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8787);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

var appname = "SolarWinds Orion Core";
var port = get_http_port(default:8787);

var dir = '/Orion';
var page_list = make_list('/Login.aspx', '/Login.asp');

var kb_base = "www/"+port+"/solarwinds_orion/";

var found_install = FALSE;
var url, match, item, extra, version, page, res, ver_src;

foreach page (page_list)
{
  url = dir + page;

  res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE, follow_redirect:2);

  spad_log(message:strcat('Response from GET request to "', url, '" on port ', port, ':\n', obj_rep(res)));

  if (
    res[2] =~ "<title>\s*SolarWinds Orion\s*</title>" &&
    ( 'User name:' >< res[2] || 'Username' >< res[2] )
  )
  {
    version = UNKNOWN_VER;
    extra = make_array();

    # try to parse version information
    item = pregmatch(pattern:'>([^<]*Orion Core[^<]+)<', string:res[2]);
    if (!isnull(item))
    {
      ver_src = item[1];
      set_kb_item(name:kb_base+"version_src", value:ver_src);

      item = pregmatch(pattern:'NPM ([0-9.]+)[^[0-9.]', string:ver_src);
      if (!isnull(item))
      {
        set_kb_item(name:kb_base+"npm_ver", value:item[1]);
        extra['NPM Version'] = item[1];
      }

      item = pregmatch(pattern:'IVIM ([0-9.]+)[^0-9.]', string:ver_src);
      if (!isnull(item))
      {
        set_kb_item(name:kb_base+"ivim_ver", value:item[1]);
        extra['IVIM Version'] = item[1];
      }
      item = pregmatch(pattern:'Orion Core ([0-9.]+)[^0-9.]', string:ver_src);
      if (!isnull(item)) version = item[1];
    }
    else
    {
      item = pregmatch(pattern:'>([^<]*Orion Platform[^<]+)<', string:res[2]);
      if (!isnull(item))
      {
        # Newer versions
        #  Orion Platform HF1, NPM: 2020.2.1
        #  NAM: 2020.2.1 | Orion Platform HF1: 2020.2
        #  Orion Platform HF1, VNQM, NPM, DPAIM, SAM HF1: 2020.2.1
        #  Orion Platform HF5, NPM HF2, NTA: 2019.4
        pattern = "Orion Platform\s*" +
                  "(?:HF([0-9]+))?" +          # Hotfix
                  "[^:]*:\s+" +
                  "([0-9]{4}(?:\.[0-9.]+)?)"; # Version
        match = pregmatch(pattern:pattern, string:res[2]);
        if (!isnull(match))
        {
          version = match[2];
          extra['Hotfix'] = match[1];

          # Retrieve NPM Hotfix
          pattern = "Orion Platform.*NPM\s*(?:HF([0-9]*))?";
          match = pregmatch(pattern:pattern, string:res[2]);
          if (!isnull(match))
          {
            if (!isnull(match[1]))
              extra['NPM Hotfix'] = match[1];
            else
              extra['NPM Hotfix'] = 0;
          }
        }
        # Older versions
        #  Orion Platform 2018.2 HF6, WPM 2.2.2, IPAM 4.7.0, SRM 6.7.0, NPM 12.3, DPAIM 11.1.0, VMAN 8.3.0, SAM 6.7.0, NetPath 1.1.3
        #  Orion Platform 2017.3.5 SP5, NPM 12.2, VMAN 8.2.0, NetPath 1.1.2, QoE 2.4, CloudMonitoring 2.0.0, NTA 4.2.
        else
        {
          pattern = "Orion Platform\s*" +
                    "([0-9]{4}(?:\.[0-9.]+)?)\s*" +  # Version
                    "(?:(SP|HF)\s*([0-9]+))?";       # Hotfix / Service Pack
          match = pregmatch(pattern:pattern, string:res[2]);
          if (!isnull(match))
          {
            version = match[1];
            patch_type = match[2];
            if (!empty_or_null(patch_type))
            {
              if (patch_type == 'SP')
                extra['Service Pack'] = match[3];
              else if (patch_type == 'HF')
                extra['Hotfix'] = match[3];
            }

            # Retrieve NPM Hotfix
            pattern = "Orion Platform.*NPM\s*([0-9.]*)?";
            match = pregmatch(pattern:pattern, string:res[2]);
            if (!isnull(match) && !isnull(match[1])) extra['NPM Version'] = match[1];
          }
        }

        # Remove copyright information
        source = ereg_replace(pattern:'(\xC2\xA9|&copy;).*', string:item[1], replace:'');

        extra['Source'] = source;
      }
    }

    register_install(
      app_name : appname,
      port     : port,
      path     : dir,
      version  : version,
      webapp   : TRUE,
      extra    : extra,
      cpe      : "cpe:/a:solarwinds:orion_platform"
    );
    found_install = TRUE;
    break;
  }
}

# If not found, detect based on redirect
if (!found_install)
{
  res = http_get_cache(port:port, item:'/', exit_on_fail:FALSE);

  if (
    !empty_or_null(res) &&
    res =~ "^HTTP/[0-9.]+ 302" &&
    'Location: /Orion/Login.asp' >< res
  )
  {
    register_install(
      app_name : appname,
      port     : port,
      path     : dir,
      version  : UNKNOWN_VER,
      webapp   : TRUE,
      cpe      : "cpe:/a:solarwinds:orion_platform"
    );

    report_extra = 'Detection was simply based on the redirection to the ' +
                   'login page since the main detection method failed.';

    found_install = TRUE;
  }
}

# As a last resort, check all web ports
if (!found_install)
{
  ports = get_kb_list("Services/www");
  if ( !isnull(ports) )
  {
    foreach web_port ( make_list(ports) )
    {
      res = get_kb_item("Cache/" + web_port + "/URL_/");
      if ( !res ) res = http_get_cache(port:web_port, item:"/", exit_on_fail:FALSE);
  
      if (
        !empty_or_null(res) &&
        res =~ "^HTTP/[0-9.]+ 302" &&
        'Location: /Orion/Login.asp' >< res
      )
      {
        register_install(
          app_name : appname,
          port     : web_port,
          path     : dir,
          version  : UNKNOWN_VER,
          webapp   : TRUE,
          cpe      : "cpe:/a:solarwinds:orion_platform"
        );

        report_extra = 'Detection was simply based on the redirection to the ' +
                       'login page since the main detection method failed.';

        found_install = TRUE;
        port = web_port;
        break;
      }
    }
  }
}

if (!found_install) audit(AUDIT_NOT_DETECT, appname, port);

report_installs(app_name:appname, port:port, extra:report_extra);
