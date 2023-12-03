rule Egress_Assess
{
    meta:
        description = "Detection patterns for the tool 'Egress-Assess' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Egress-Assess"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string1 = /.{0,1000}\s\-client\sftp\s\-ip\s.{0,1000}\s\-Username\s.{0,1000}\s\-Password\s.{0,1000}\s\-Datatype\sssn\s\-Size\s.{0,1000}\s\-Verbose.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string2 = /.{0,1000}\s\-client\shttp\s\-ip\s.{0,1000}\s\-Datatype\scc\s\-Size\s.{0,1000}\s\-Port\s.{0,1000}\s\-Loop\s.{0,1000}\s\-Fast\s\-Verbose.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string3 = /.{0,1000}\s\-client\sicmp\s\-ip\s.{0,1000}\s\-Datatype\sssn\s\-Report\s\-Verbose.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string4 = /.{0,1000}\s\-client\ssmb\s\-ip\s.{0,1000}\s\-Datatype\s.{0,1000}c:\\.{0,1000}\..{0,1000}\s\-Verbose.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string5 = /.{0,1000}\s\-Client\sSMTPOutlook\s\-IP\s.{0,1000}\s\-NoPing\s\-DataType\s.{0,1000}ssn.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string6 = /.{0,1000}\sEgress\-Assess\'s\sFTP\sserver.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string7 = /.{0,1000}\setumbot\.py.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string8 = /.{0,1000}\sputterpanda\.py.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string9 = /.{0,1000}\sUse\-DarkHotel.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string10 = /.{0,1000}\.py\s\-\-client\sftp\s\-\-username\s.{0,1000}\s\-\-password\s.{0,1000}\s\-\-ip\s.{0,1000}\s\-\-datatype\sssn.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string11 = /.{0,1000}\.py\s\-\-client\shttps\s\-\-data\-size\s.{0,1000}\s\-\-ip\s.{0,1000}\s\-\-datatype\scc.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string12 = /.{0,1000}\/bin\/read_i\.php\?a1\=step2\-down\-b\&a2\=.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string13 = /.{0,1000}\/bin\/read_i\.php\?a1\=step2\-down\-c\&a2\=.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string14 = /.{0,1000}\/bin\/read_i\.php\?a1\=step2\-down\-j\&a2\=.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string15 = /.{0,1000}\/bin\/read_i\.php\?a1\=step2\-down\-k\&a2\=.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string16 = /.{0,1000}\/bin\/read_i\.php\?a1\=step2\-down\-r\&a2\=.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string17 = /.{0,1000}\/bin\/read_i\.php\?a1\=step2\-down\-u\&a2\=.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string18 = /.{0,1000}\/commandcontrol\/malware.{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string19 = /.{0,1000}\/creditcards\.py.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string20 = /.{0,1000}\/darkhotel\.py.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string21 = /.{0,1000}\/Egress\-Assess.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string22 = /.{0,1000}\/servers\/dns_server\.py.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string23 = /.{0,1000}\/servers\/icmp_server\.py.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string24 = /.{0,1000}\/servers\/smb_server\.py.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string25 = /.{0,1000}\/zejius\/2HZG41Zw\/6Vtmo6w4yQ5tnsBHms64\.php.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string26 = /.{0,1000}\/zejius\/2HZG41Zw\/fJsnC6G4sFg2wsyn4shb\.bin.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string27 = /.{0,1000}\/zejius\/5GPR0iy9\/6Vtmo6w4yQ5tnsBHms64\.php.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string28 = /.{0,1000}\/zejius\/5GPR0iy9\/fJsnC6G4sFg2wsyn4shb\.bin.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string29 = /.{0,1000}\\creditcards\.py.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string30 = /.{0,1000}\\Egress\-Assess.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string31 = /.{0,1000}\\servers\\dns_server\.py.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string32 = /.{0,1000}\\servers\\icmp_server\.py.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string33 = /.{0,1000}\\servers\\smb_server\.py.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string34 = /.{0,1000}apt\/etumbot\.py.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string35 = /.{0,1000}apt\/putterpanda\.py.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string36 = /.{0,1000}autolace\.twilightparadox\.com.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string37 = /.{0,1000}automachine\.servequake\.com.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string38 = /.{0,1000}b64encode.{0,1000}\.:::\-989\-:::\..{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string39 = /.{0,1000}bHVrZXJlYWxseWlzdGhlbWFubXl0aGFuZGxlZ2VuZA.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string40 = /.{0,1000}bm90cmVkYW1lY2hlYXRzdG93aW4\-.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string41 = /.{0,1000}c2VydmVyMS5jaWEuZ292.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string42 = /.{0,1000}catchetumbotifyoucan\>.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string43 = /.{0,1000}cGlpLmZkYS5nb3Y\=.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string44 = /.{0,1000}Copy\-Item\s\-Path\s.{0,1000}\s\-Destination\s\\\\\$IP\\transfer.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string45 = /.{0,1000}d2h5aXNwZW5uc3RhdGVzb2JhZGF0Zm9vdGJhbGw.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string46 = /.{0,1000}darkhotel\sbackdoor.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string47 = /.{0,1000}DarkHotel\sC2.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string48 = /.{0,1000}darkhotel\sdata\sexfil\sserver.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string49 = /.{0,1000}darkhotel_headers.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string50 = /.{0,1000}dGhlU2VtaW5vbGVzYmVhdG5vcmVkYW1l.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string51 = /.{0,1000}dGhlYnJvbmNvc2FyZWJldHRlcnRoYW5yYXZlbnM\-.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string52 = /.{0,1000}dGhpc2lzYXRlc3RzdHJpbmdkb250Y2F0Y2htZQ\-\-.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string53 = /.{0,1000}Egress\-Assess\sExfil\sData.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string54 = /.{0,1000}Egress\-Assess\sReport.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string55 = /.{0,1000}Egress\-Assess\stransfer\sshare.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string56 = /.{0,1000}EgressAssess\sWith\sAttachment.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string57 = /.{0,1000}Egress\-Assess\..{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string58 = /.{0,1000}EgressAssess\.ps1.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string59 = /.{0,1000}Egress\-Assess\-master.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string60 = /.{0,1000}ENDTHISFILETRANSMISSIONEGRESSASSESS.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string61 = /.{0,1000}ENDTHISFILETRANSMISSIONEGRESSASSESS.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string62 = /.{0,1000}function\sUse\-Zeus.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string63 = /.{0,1000}gohaleygoandhackawaythegibson.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string64 = /.{0,1000}Invoke\-EssessAgress.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string65 = /.{0,1000}microbrownys\.strangled\.net.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string66 = /.{0,1000}microchsse\.strangled\.net.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string67 = /.{0,1000}microlilics\.crabdance\.com.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string68 = /.{0,1000}micronaoko\.jumpingcrab\.com.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string69 = /.{0,1000}microplants\.strangled\.net.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string70 = /.{0,1000}MIIEoQIBAAKCAQEArJqP\/6XFBa88x\/DUootMmSzYa3MxcTV9FjNYUomqbQlGzuHa.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string71 = /.{0,1000}New\-PSDrive\s\-Name\sT\s\-PSProvider\sFileSystem\s\-Root\s\\\\\$IP\\transfer\s.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string72 = /.{0,1000}notredamecheatstowin\>.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string73 = /.{0,1000}putterpanda_whoami.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string74 = /.{0,1000}RU5EVEhJU0ZJTEVUUkFOU01JU1NJT05FR1JFU1NBU1NFU1M\=.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string75 = /.{0,1000}server\@egress\-asses\.com.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string76 = /.{0,1000}smbclient\s\\\\\\\\\\\\\\\\.{0,1000}\\\\\\\\TRANSFER\s\-N\s\-p\s.{0,1000}\s\-c\s\\.{0,1000}put\s.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string77 = /.{0,1000}tester\@egress\-assess\.com.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string78 = /.{0,1000}thisisateststringdontcatchme.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string79 = /.{0,1000}TVqQAAMAAAAEAAAA.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string80 = /.{0,1000}U2VtaW5vbGVzd291bGRkZXN0cm95cGVubnN0YXRl.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string81 = /.{0,1000}Y2F0Y2hldHVtYm90aWZ5b3VjYW4\-.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string82 = /.{0,1000}Yml0c3kubWl0LmVkdQ\=\=.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string83 = /.{0,1000}YmpwZW5uaXNhbmF3ZXNvbWVmaWdodGVy.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string84 = /.{0,1000}Z29oYWxleWdvYW5kaGFja2F3YXl0aGVnaWJzb24.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string85 = /.{0,1000}ZGF0YS5mZGEuZ292.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string86 = /.{0,1000}ZGIuc3NhLmdvdg\=\=.{0,1000}/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string87 = /.{0,1000}ZXZpZGVuY2UuZmJpLmdvdg\=\=.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
