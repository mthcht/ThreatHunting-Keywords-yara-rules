rule yakit
{
    meta:
        description = "Detection patterns for the tool 'yakit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "yakit"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string1 = /\sset\-proxy\.ps1/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string2 = /\"http\:\/\/mitm\"/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string3 = /\/MITMPluginLogViewer/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string4 = /\/MITMServerHijacking/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string5 = /\/set\-proxy\.ps1/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string6 = /\/yak_darwin_amd64\.zip/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string7 = /\/yak_linux_amd64\.zip/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string8 = /\/yak_windows_amd64\.zip/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string9 = /\?\?\sMITM\s\?\?\?\?/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string10 = /\\default\-yakit\.db/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string11 = /\\set\-proxy\.ps1/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string12 = /\\System32\\yak\.exe/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string13 = /\\yak\.exe/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string14 = /MITMServerHijacking\/MITMPluginLocalList/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string15 = /pwd86u1qwZ9PWevKqm1A3yAw\=\=/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string16 = /PwDaBjJzgufjES89Rs4Lpq63O300R\/kOz30WCLo6BxxX6QVEilwSlpClnG5cZaikTA\=\=/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string17 = /pWDkVEtllTAK5h6cnhxNxDA\=\=/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string18 = /Yakit\-.{0,1000}\-windows\-amd64\.exe/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string19 = /Yakit\/1\.0\.0/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string20 = /YAKIT_MITM/ nocase ascii wide
        // Description: security platform with fuzzers - webshell and MITM (chinese burp)
        // Reference: https://github.com/Gerenios/AADInternals
        $string21 = /yakit\-remote\.json/ nocase ascii wide

    condition:
        any of them
}
