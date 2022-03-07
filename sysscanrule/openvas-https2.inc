include("ssl_funcs.inc");

function https_req_get(port, request, recv3)
{
    if(get_port_state(port))
    {
        transport = ssl_transport(ssl:TRUE, verify:FALSE);
	 soc = open_sock_tcp(port, transport:transport);
	 if(soc)
	 {
	    send(socket:soc, data:string(request,"\r\n"));
            x = 0;
            while(ret = recv(socket:soc , length:2048, timeout:5)) { 
              x++;
              result += ret;
              if(x > 25)break;
            }
	    close(soc);
	    if(recv3){
	        ver_parts = eregmatch(pattern:"(.*)0d0a0d0a(.*)", string:hexstr(result));
	        head = (hex2raw(s:ver_parts[1]));
	        body = (hex2raw(s:ver_parts[2]));
		result = make_list(head,body);
		return(result);
	    }else{
	        return(result);	    
	    }
        }
    }
}
