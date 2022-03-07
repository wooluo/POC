include("compat.inc");


if (description)
{
  script_id(51799313);
  script_version("1.3");
  script_name(english:"Apache Shiro rememberMe parameter key can be enumerated vulnerability");
  script_summary(english:"Apache Shiro rememberMe parameter key can be enumerated vulnerability");
  script_set_attribute(attribute:"description", value:"Apache Shiro rememberMe parameter key can be enumerated vulnerability.");
  script_set_attribute(attribute:"solution", value:"Modify the key value to be a random value.");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"risk_factor", value:"Medium");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"Web Servers");
  script_dependencies("apache_shiro_detect.nasl");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  script_require_ports("shiro/installed/port");
  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("openvas-https2.inc");


port = get_kb_item("shiro/installed/port");

result_r = check_remote(port:port);
if (result_r['vuln']){
	security_hole(port:port, extra:result_r['report']);
	exit(0);
}

function mk_payload(key){

	serObj = "aced0005737200326f72672e6170616368652e736869726f2e7375626a6563742e53696d706c655072696e636970616c436f6c6c656374696f6ea87f5825c6a3084a0300014c000f7265616c6d5072696e636970616c7374000f4c6a6176612f7574696c2f4d61703b78707077010078";
    iv = hex2raw(s:"77cfd798a8e94c44974c4ed0a60ab81a");
	key = base64_decode(str:key);
	pad = 16 - strlen(hex2raw(s:serObj))%16;
	for (i=0; i<pad; i++){
	    padstr += "10";
	}
	data = serObj + padstr;
	serObj = hex2raw(s:data);
	res = aes_cbc_encrypt(data:serObj, key:key, iv:iv);
	serObj_send = base64(str:iv+res[0]);
	return serObj_send;

}


function check_remote(port){
	keys = make_list("kPH+bIxk5D2deZiIxcaaaA==","4AvVhmFLUs0KTA3Kprsdag==","Z3VucwAAAAAAAAAAAAAAAA==","fCq+/xW488hMTCD+cmJ3aQ==","0AvVhmFLUs0KTA3Kprsdag==","1AvVhdsgUs0FSA3SDFAdag==","1QWLxg+NYmxraMoxAXu/Iw==","25BsmdYwjnfcWmnhAciDDg==","2AvVhdsgUs0FSA3SDFAdag==","3AvVhmFLUs0KTA3Kprsdag==","3JvYhmBLUs0ETA5Kprsdag==","r0e3c16IdVkouZgk1TKVMg==","5aaC5qKm5oqA5pyvAAAAAA==","5AvVhmFLUs0KTA3Kprsdag==","6AvVhmFLUs0KTA3Kprsdag==","6NfXkC7YVCV5DASIrEm1Rg==","6ZmI6I2j5Y+R5aSn5ZOlAA==","cmVtZW1iZXJNZQAAAAAAAA==","7AvVhmFLUs0KTA3Kprsdag==","8AvVhmFLUs0KTA3Kprsdag==","8BvVhmFLUs0KTA3Kprsdag==","9AvVhmFLUs0KTA3Kprsdag==","OUHYQzxQ/W9e/UjiAGu6rg==","a3dvbmcAAAAAAAAAAAAAAA==","aU1pcmFjbGVpTWlyYWNsZQ==","bWljcm9zAAAAAAAAAAAAAA==","bWluZS1hc3NldC1rZXk6QQ==","bXRvbnMAAAAAAAAAAAAAAA==","ZUdsaGJuSmxibVI2ZHc9PQ==","wGiHplamyXlVB11UXWol8g==","U3ByaW5nQmxhZGUAAAAAAA==","MTIzNDU2Nzg5MGFiY2RlZg==","L7RioUULEFhRyxM7a2R/Yg==","a2VlcE9uR29pbmdBbmRGaQ==","WcfHGU25gNnTxTlmJMeSpw==","OY//C4rhfwNxCQAQCrQQ1Q==","5J7bIJIV0LQSN3c9LPitBQ==","f/SY5TIve5WWzT4aQlABJA==","bya2HkYo57u6fWh5theAWw==","WuB+y2gcHRnY2Lg9+Aqmqg==","kPv59vyqzj00x11LXJZTjJ2UHW48jzHN","3qDVdLawoIr1xFd6ietnwg==","YI1+nBV//m7ELrIyDHm6DQ==","6Zm+6I2j5Y+R5aS+5ZOlAA==","2A2V+RFLUs+eTA3Kpr+dag==","6ZmI6I2j3Y+R1aSn5BOlAA==","SkZpbmFsQmxhZGUAAAAAAA==","2cVtiE83c4lIrELJwKGJUw==","fsHspZw/92PrS3XrPW+vxw==","XTx6CKLo/SdSgub+OPHSrw==","sHdIjUN6tzhl8xZMG3ULCQ==","O4pdf+7e+mZe8NyxMTPJmQ==","HWrBltGvEZc14h9VpMvZWw==","rPNqM6uKFCyaL10AK51UkQ==","Y1JxNSPXVwMkyvES/kJGeQ==","lT2UvDUmQwewm6mMoiw4Ig==","MPdCMZ9urzEA50JDlDYYDg==","xVmmoltfpb8tTceuT5R7Bw==","c+3hFGPjbgzGdrC+MHgoRQ==","ClLk69oNcA3m+s0jIMIkpg==","Bf7MfkNR0axGGptozrebag==","1tC/xrDYs8ey+sa3emtiYw==","ZmFsYWRvLnh5ei5zaGlybw==","cGhyYWNrY3RmREUhfiMkZA==","IduElDUpDDXE677ZkhhKnQ==","yeAAo1E8BOeAYfBlm4NG9Q==","cGljYXMAAAAAAAAAAAAAAA==","2itfW92XazYRi5ltW0M2yA==","XgGkgqGqYrix9lI6vxcrRw==","ertVhmFLUs0KTA3Kprsdag==","5AvVhmFLUS0ATA4Kprsdag==","s0KTA3mFLUprK4AvVhsdag==","hBlzKg78ajaZuTE0VLzDDg==","9FvVhtFLUs0KnA3Kprsdyg==","d2ViUmVtZW1iZXJNZUtleQ==","yNeUgSzL/CfiWw1GALg6Ag==","NGk/3cQ6F5/UNPRh8LpMIg==","4BvVhmFLUs0KTA3Kprsdag==","MzVeSkYyWTI2OFVLZjRzZg==","empodDEyMwAAAAAAAAAAAA==","A7UzJgh1+EWj5oBFi+mSgw==","c2hpcm9fYmF0aXMzMgAAAA==","i45FVt72K2kLgvFrJtoZRw==","U3BAbW5nQmxhZGUAAAAAAA==","ZnJlc2h6Y24xMjM0NTY3OA==","Jt3C93kMR9D5e8QzwfsiMw==","MTIzNDU2NzgxMjM0NTY3OA==","vXP33AonIp9bFwGl7aT7rA==","V2hhdCBUaGUgSGVsbAAAAA==","Q01TX0JGTFlLRVlfMjAxOQ==","ZAvph3dsQs0FSL3SDFAdag==","Is9zJ3pzNh2cgTHB4ua3+Q==","NsZXjXVklWPZwOfkvk6kUA==","GAevYnznvgNCURavBhCr1w==","66v1O8keKNV3TTcGPK1wzg==","SDKOLKn2J1j/2BHjeZwAoQ==");
	
	foreach key (keys){
		payload = mk_payload(key:key);
		cookie = "rememberMe="+payload;
		if (get_kb_list("SSL/Transport/"+port)){
			url = string('/login');
			
			var req =
					'GET ' + url +' HTTP/1.1\r\n' +
					'Host: ' + get_host_ip()+':'+ port+ '\r\n' +
					'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0' + '\r\n' +
					'Accept-Encoding: gzip, deflate' + '\r\n' +
					'Cookie: '+cookie + '\r\n' +
					'Connection: keep-alive'+ '\r\n' +
					'Accept: */*' + '\r\n' + 
					'\r\n';
					
			ssl_reqs = https_req_get(request:req, port:port);
			if ("rememberMe=deleteMe" >!< ssl_reqs){
				report = "Guess The Key: " + key;
				return {'vuln':true, 'report':report};
			}
		}
		else{
			url = string('/login');
			shiro_send = http_send_recv3(method: "GET",port: port, item: url,add_headers: make_array("Cookie",cookie));
			if("rememberMe=deleteMe" >!< shiro_send[1]){
				set_kb_item(name:"Shiro/key",value:key);
				report = "Guess The Key: " + key;
				return {'vuln':true, 'report':report};
			}

		}
	}
}
