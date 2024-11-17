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
        $string1 = /\s\-client\sftp\s\-ip\s.{0,100}\s\-Username\s.{0,100}\s\-Password\s.{0,100}\s\-Datatype\sssn\s\-Size\s.{0,100}\s\-Verbose/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string2 = /\s\-client\shttp\s\-ip\s.{0,100}\s\-Datatype\scc\s\-Size\s.{0,100}\s\-Port\s.{0,100}\s\-Loop\s.{0,100}\s\-Fast\s\-Verbose/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string3 = /\s\-client\sicmp\s\-ip\s.{0,100}\s\-Datatype\sssn\s\-Report\s\-Verbose/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string4 = /\s\-client\ssmb\s\-ip\s.{0,100}\s\-Datatype\s.{0,100}c\:\\.{0,100}\..{0,100}\s\-Verbose/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string5 = /\s\-Client\sSMTPOutlook\s\-IP\s.{0,100}\s\-NoPing\s\-DataType\s.{0,100}ssn/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string6 = /\sEgress\-Assess\'s\sFTP\sserver/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string7 = /\setumbot\.py/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string8 = /\sputterpanda\.py/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string9 = /\sUse\-DarkHotel/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string10 = /\.py\s\-\-client\sftp\s\-\-username\s.{0,100}\s\-\-password\s.{0,100}\s\-\-ip\s.{0,100}\s\-\-datatype\sssn/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string11 = /\.py\s\-\-client\shttps\s\-\-data\-size\s.{0,100}\s\-\-ip\s.{0,100}\s\-\-datatype\scc/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string12 = /\/bin\/read_i\.php\?a1\=step2\-down\-b\&a2\=/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string13 = /\/bin\/read_i\.php\?a1\=step2\-down\-c\&a2\=/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string14 = /\/bin\/read_i\.php\?a1\=step2\-down\-j\&a2\=/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string15 = /\/bin\/read_i\.php\?a1\=step2\-down\-k\&a2\=/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string16 = /\/bin\/read_i\.php\?a1\=step2\-down\-r\&a2\=/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string17 = /\/bin\/read_i\.php\?a1\=step2\-down\-u\&a2\=/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string18 = /\/commandcontrol\/malware.{0,100}\.py/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string19 = /\/creditcards\.py/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string20 = /\/darkhotel\.py/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string21 = /\/Egress\-Assess/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string22 = /\/servers\/dns_server\.py/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string23 = /\/servers\/icmp_server\.py/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string24 = /\/servers\/smb_server\.py/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string25 = /\/zejius\/2HZG41Zw\/6Vtmo6w4yQ5tnsBHms64\.php/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string26 = /\/zejius\/2HZG41Zw\/fJsnC6G4sFg2wsyn4shb\.bin/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string27 = /\/zejius\/5GPR0iy9\/6Vtmo6w4yQ5tnsBHms64\.php/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string28 = /\/zejius\/5GPR0iy9\/fJsnC6G4sFg2wsyn4shb\.bin/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string29 = /\\creditcards\.py/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string30 = /\\Egress\-Assess/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string31 = /\\servers\\dns_server\.py/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string32 = /\\servers\\icmp_server\.py/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string33 = /\\servers\\smb_server\.py/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string34 = /apt\/etumbot\.py/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string35 = /apt\/putterpanda\.py/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string36 = /autolace\.twilightparadox\.com/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string37 = /automachine\.servequake\.com/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string38 = /b64encode.{0,100}\.\:\:\:\-989\-\:\:\:\./ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string39 = /bHVrZXJlYWxseWlzdGhlbWFubXl0aGFuZGxlZ2VuZA/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string40 = /bm90cmVkYW1lY2hlYXRzdG93aW4\-/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string41 = /c2VydmVyMS5jaWEuZ292/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string42 = /catchetumbotifyoucan\>/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string43 = /cGlpLmZkYS5nb3Y\=/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string44 = /Copy\-Item\s\-Path\s.{0,100}\s\-Destination\s\\\\\$IP\\transfer/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string45 = /d2h5aXNwZW5uc3RhdGVzb2JhZGF0Zm9vdGJhbGw/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string46 = /darkhotel\sbackdoor/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string47 = /DarkHotel\sC2/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string48 = /darkhotel\sdata\sexfil\sserver/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string49 = /darkhotel_headers/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string50 = /dGhlU2VtaW5vbGVzYmVhdG5vcmVkYW1l/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string51 = /dGhlYnJvbmNvc2FyZWJldHRlcnRoYW5yYXZlbnM\-/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string52 = /dGhpc2lzYXRlc3RzdHJpbmdkb250Y2F0Y2htZQ\-\-/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string53 = /Egress\-Assess\sExfil\sData/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string54 = /Egress\-Assess\sReport/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string55 = /Egress\-Assess\stransfer\sshare/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string56 = /EgressAssess\sWith\sAttachment/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string57 = /Egress\-Assess\./ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string58 = /EgressAssess\.ps1/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string59 = /Egress\-Assess\-master/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string60 = /ENDTHISFILETRANSMISSIONEGRESSASSESS/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string61 = /ENDTHISFILETRANSMISSIONEGRESSASSESS/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string62 = /function\sUse\-Zeus/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string63 = /gohaleygoandhackawaythegibson/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string64 = /Invoke\-EssessAgress/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string65 = /microbrownys\.strangled\.net/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string66 = /microchsse\.strangled\.net/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string67 = /microlilics\.crabdance\.com/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string68 = /micronaoko\.jumpingcrab\.com/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string69 = /microplants\.strangled\.net/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string70 = /MIIEoQIBAAKCAQEArJqP\/6XFBa88x\/DUootMmSzYa3MxcTV9FjNYUomqbQlGzuHa/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string71 = /New\-PSDrive\s\-Name\sT\s\-PSProvider\sFileSystem\s\-Root\s\\\\\$IP\\transfer\s/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string72 = /notredamecheatstowin\>/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string73 = /putterpanda_whoami/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string74 = /RU5EVEhJU0ZJTEVUUkFOU01JU1NJT05FR1JFU1NBU1NFU1M\=/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string75 = /server\@egress\-asses\.com/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string76 = /smbclient\s\\\\\\\\\\\\\\\\.{0,100}\\\\\\\\TRANSFER\s\-N\s\-p\s.{0,100}\s\-c\s\\.{0,100}put\s/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string77 = /tester\@egress\-assess\.com/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string78 = /thisisateststringdontcatchme/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string79 = /TVqQAAMAAAAEAAAA/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string80 = /U2VtaW5vbGVzd291bGRkZXN0cm95cGVubnN0YXRl/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string81 = /Y2F0Y2hldHVtYm90aWZ5b3VjYW4\-/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string82 = /Yml0c3kubWl0LmVkdQ\=\=/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string83 = /YmpwZW5uaXNhbmF3ZXNvbWVmaWdodGVy/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string84 = /Z29oYWxleWdvYW5kaGFja2F3YXl0aGVnaWJzb24/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string85 = /ZGF0YS5mZGEuZ292/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string86 = /ZGIuc3NhLmdvdg\=\=/ nocase ascii wide
        // Description: Egress-Assess is a tool used to test egress data detection capabilities
        // Reference: https://github.com/FortyNorthSecurity/Egress-Assess
        $string87 = /ZXZpZGVuY2UuZmJpLmdvdg\=\=/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
