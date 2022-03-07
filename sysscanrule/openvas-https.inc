
function https_req_get(port, request)
{
    if(get_port_state(port))
    {
        
	 soc = open_sock_tcp(port,transport:ENCAPS_SSLv23);
	 if(soc)
	 {
	    send(socket:soc, data:string(request,"\r\n"));
            x = 0;
            while(ret = http_recv(socket:soc)) { 
              x++;
              result += ret;
              if(x > 25)break;
            }
	    close(soc);
	    return(result);
        }
    }
}
