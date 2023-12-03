rule PyExfil
{
    meta:
        description = "Detection patterns for the tool 'PyExfil' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PyExfil"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string1 = /.{0,1000}\/audio\/exfiltrator\.py.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string2 = /.{0,1000}\/bgp_exfil\.py.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string3 = /.{0,1000}\/http_exfiltration\.py.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string4 = /.{0,1000}\/icmp_exfiltration\.py.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string5 = /.{0,1000}\/pop_exfil_client\.py.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string6 = /.{0,1000}\/pop_exfil_server\.py.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string7 = /.{0,1000}\/PyExfil\.git.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string8 = /.{0,1000}\/PyExfil\/pyexfil\/.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string9 = /.{0,1000}\/spoofIPs_client\.py.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string10 = /.{0,1000}\/wifiPayload\/client\.py.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string11 = /.{0,1000}\/wifiPayload\/server\.py.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string12 = /.{0,1000}\\audio\\exfiltrator\.py.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string13 = /.{0,1000}\\bgp_exfil\.py.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string14 = /.{0,1000}\\http_exfiltration\.py.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string15 = /.{0,1000}\\icmp_exfiltration\.py.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string16 = /.{0,1000}\\pop_exfil_client\.py.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string17 = /.{0,1000}\\pop_exfil_server\.py.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string18 = /.{0,1000}\\PyExfil\\pyexfil\\.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string19 = /.{0,1000}\\spoofIPs_client\.py.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string20 = /.{0,1000}\\wifiPayload\\client\.py.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string21 = /.{0,1000}\\wifiPayload\\server\.py.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string22 = /.{0,1000}A\sPython\spackage\sfor\sdata\sexfiltration\..{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string23 = /.{0,1000}cd\sPyExfil.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string24 = /.{0,1000}encode\sbaseImage\.jpg\s\/etc\/passwd\snewImage\.jpg.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string25 = /.{0,1000}FILE_TO_EXFIL\s\=\s\".{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string26 = /.{0,1000}pip\sinstall\s\-\-user\sPyExfil.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string27 = /.{0,1000}pyexfil\.Comm\.AllJoyn.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string28 = /.{0,1000}pyexfil\.Comm\.DNSoTLS\.client.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string29 = /.{0,1000}pyexfil\.Comm\.DNSoTLS\.server.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string30 = /.{0,1000}pyexfil\.Comm\.GQUIC.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string31 = /.{0,1000}pyexfil\.Comm\.jetdirect\.communicator.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string32 = /.{0,1000}pyexfil\.Comm\.MDNS.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string33 = /.{0,1000}pyexfil\.Comm\.NTP_Body\.client.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string34 = /.{0,1000}pyexfil\.Comm\.NTP_Body\.server.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string35 = /.{0,1000}pyexfil\.HTTPS\.https_client.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string36 = /.{0,1000}pyexfil\.HTTPS\.https_server.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string37 = /.{0,1000}pyexfil\.includes\.data_generator.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string38 = /.{0,1000}pyexfil\.includes\.encryption_wrappers.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string39 = /.{0,1000}pyexfil\.includes\.exceptions.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string40 = /.{0,1000}pyexfil\.includes\.general.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string41 = /.{0,1000}pyexfil\.includes\.image_manipulation.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string42 = /.{0,1000}pyexfil\.includes\.prepare.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string43 = /.{0,1000}PyExfil\.MoriRT\.com.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string44 = /.{0,1000}pyexfil\.network.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string45 = /.{0,1000}pyexfil\.network\.DB_LSP\.dblsp.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string46 = /.{0,1000}pyexfil\.network\.FTP\.ftp_exfil.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string47 = /.{0,1000}pyexfil\.network\.HTTP_Cookies\.http_exfiltration.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string48 = /.{0,1000}pyexfil\.network\.HTTPResp\.client.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string49 = /.{0,1000}pyexfil\.network\.ICMP\.icmp_exfiltration.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string50 = /.{0,1000}pyexfil\.network\.SpoofIP\.spoofIPs_client.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string51 = /.{0,1000}pyexfil\.physical\.qr\.generator.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string52 = /.{0,1000}pyexfil\.physical\.wifiPayload\.client.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string53 = /.{0,1000}pyexfil\.Stega\.binoffset\.binoffset.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string54 = /.{0,1000}PYEXFIL_DEFAULT_PASSWORD.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string55 = /.{0,1000}pyExfil\-latest\.zip.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string56 = /.{0,1000}PyExfil\-master.{0,1000}/ nocase ascii wide
        // Description: A Python Package for Data Exfiltration
        // Reference: https://github.com/ytisf/PyExfil
        $string57 = /.{0,1000}ytisf\/PyExfil.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
