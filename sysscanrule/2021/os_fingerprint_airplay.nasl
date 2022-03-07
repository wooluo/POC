#
# 
#

include("compat.inc");

if (description)
{
  script_id(127857);
  script_version("1.3");
  script_cvs_date("Date: 2020/01/22");

  script_name(english:"OS Identification : Apple AirPlay");
  script_summary(english:"Determines the remote operating system.");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to identify the remote operating system based on the
capabilities of the remote AirPlay server.");
  script_set_attribute(attribute:"description", value:
"This script attempts to identify the operating system type and version
by looking at the capabilities of the remote Apple AirPlay server.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apple_airplay_web_detect.nbin");
  script_require_keys("installed_sw/Apple AirPlay");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

app = "Apple AirPlay";

# Multiple detections are possible on multiple ports
installs = get_combined_installs(app_name:app, exit_if_not_found:TRUE);

# All instances should serve the same info, so just grab the first one
install = installs[1][0];
if (empty_or_null(install))
  audit(AUDIT_NOT_DETECT, app);

var rdevice, device;

fingerprints = [];
confidence = 90;

# RModel
#  Before checking 'model', check 'rmodel' which appears to be for
#  clients or proxies for AirPlay devices. 
rmodel = install['rmodel'];

if (!empty_or_null(rmodel))
{
  if (rmodel =~ "^AirReceiver") rdevice = "AirReceiver";

  append_element(var:fingerprints, value:'rmodel:' + rmodel);
}

# Model
model = install['model'];

if (!empty_or_null(model))
{
  if (model =~ "^AppleTV") device = "Apple TV";
  else if (model =~ "^AudioAccessory") device = "Apple HomePod";

  if (!empty_or_null(rdevice) && !empty_or_null(device))
  {
    device = rdevice + " for " + device;
  }
 
  append_element(var:fingerprints, value:'model:' + model);
}

# Process models
if (empty_or_null(fingerprints))
 exit(0, "Missing expected model information.");

fingerprint = join(fingerprints, sep:" / ");
set_kb_item(name:"Host/OS/Apple_AirPlay/Fingerprint", value:fingerprint);

# Use rdevice if device is not available
if (!empty_or_null(rmodel) && empty_or_null(model))
  device = rdevice;

if (empty_or_null(device))
  exit(0, "Could not identify device.");

set_kb_item(name:"Host/OS/Apple_AirPlay", value:device);
set_kb_item(name:"Host/OS/Apple_AirPlay/Confidence", value:confidence);
set_kb_item(name:"Host/OS/Apple_AirPlay/Type", value:"embedded");
