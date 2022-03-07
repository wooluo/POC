#!/bin/bash
curdir=$(dirname "$0")
plugindir=/opt/GizaNE/lib/GizaNE/plugins

#fs=$(grep -e "\(CVE-2019-6111\)\|\(CVE-2019-6110\)\|\(CVE-2019-6109\)\|\(CVE-2019-12255\)" "$plugindir"/ -r | awk -F: '{print $1}' |sort | uniq)
fs=$(grep -e "CVE-2019-" "$plugindir"/ -r | awk -F: '{print $1}' |sort | uniq)
if [ -z "$fs" ]; then
	echo "No find nasl!!!"
	exit 0
fi

for f in $fs; do
	cp -f "$f" "$curdir"/
done

cp -f /opt/GizaNE/lib/GizaNE/plugins/amap.nasl  /opt/GizaNE/lib/GizaNE/plugins/wwwboardpwd.nasl /opt/GizaNE/lib/GizaNE/plugins/jetroot.nasl /opt/GizaNE/lib/GizaNE/plugins/minishare_overflow.nasl /opt/GizaNE/lib/GizaNE/plugins/tomcat_srcjsp_malformed_request.nasl /opt/GizaNE/lib/GizaNE/plugins/tomcat_status.nasl /opt/GizaNE/lib/GizaNE/plugins/tomcat_source_exposure.nasl /opt/GizaNE/lib/GizaNE/plugins/http_cookies_settings.nasl "$curdir"/
