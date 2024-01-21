rule dns_black_cat
{
    meta:
        description = "Detection patterns for the tool 'dns-black-cat' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dns-black-cat"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Multi platform toolkit for an interactive DNS shell commands exfiltration - by using DNS-Cat you will be able to execute system commands in shell mode over DNS protocol
        // Reference: https://github.com/lawrenceamer/dns-black-cat
        $string1 = /\sDNS\-Black\-CAT\sServer\s/ nocase ascii wide
        // Description: Multi platform toolkit for an interactive DNS shell commands exfiltration - by using DNS-Cat you will be able to execute system commands in shell mode over DNS protocol
        // Reference: https://github.com/lawrenceamer/dns-black-cat
        $string2 = /\/DBC\-Server\.py/ nocase ascii wide
        // Description: Multi platform toolkit for an interactive DNS shell commands exfiltration - by using DNS-Cat you will be able to execute system commands in shell mode over DNS protocol
        // Reference: https://github.com/lawrenceamer/dns-black-cat
        $string3 = /\/dns\-black\-cat\.git/ nocase ascii wide
        // Description: Multi platform toolkit for an interactive DNS shell commands exfiltration - by using DNS-Cat you will be able to execute system commands in shell mode over DNS protocol
        // Reference: https://github.com/lawrenceamer/dns-black-cat
        $string4 = /\/dns\-cat\.exe/ nocase ascii wide
        // Description: Multi platform toolkit for an interactive DNS shell commands exfiltration - by using DNS-Cat you will be able to execute system commands in shell mode over DNS protocol
        // Reference: https://github.com/lawrenceamer/dns-black-cat
        $string5 = /\\dns\-cat\.exe/ nocase ascii wide
        // Description: Multi platform toolkit for an interactive DNS shell commands exfiltration - by using DNS-Cat you will be able to execute system commands in shell mode over DNS protocol
        // Reference: https://github.com/lawrenceamer/dns-black-cat
        $string6 = /agent\.exe\s\-dns\s\-srvhost\s/ nocase ascii wide
        // Description: Multi platform toolkit for an interactive DNS shell commands exfiltration - by using DNS-Cat you will be able to execute system commands in shell mode over DNS protocol
        // Reference: https://github.com/lawrenceamer/dns-black-cat
        $string7 = /dns_server\.py\s\-d\s/ nocase ascii wide
        // Description: Multi platform toolkit for an interactive DNS shell commands exfiltration - by using DNS-Cat you will be able to execute system commands in shell mode over DNS protocol
        // Reference: https://github.com/lawrenceamer/dns-black-cat
        $string8 = /dns\-black\-cat\-main/ nocase ascii wide
        // Description: Multi platform toolkit for an interactive DNS shell commands exfiltration - by using DNS-Cat you will be able to execute system commands in shell mode over DNS protocol
        // Reference: https://github.com/lawrenceamer/dns-black-cat
        $string9 = /dns\-cat\.exe\s\-/ nocase ascii wide
        // Description: Multi platform toolkit for an interactive DNS shell commands exfiltration - by using DNS-Cat you will be able to execute system commands in shell mode over DNS protocol
        // Reference: https://github.com/lawrenceamer/dns-black-cat
        $string10 = /lawrenceamer\/dns\-black\-cat/ nocase ascii wide

    condition:
        any of them
}
