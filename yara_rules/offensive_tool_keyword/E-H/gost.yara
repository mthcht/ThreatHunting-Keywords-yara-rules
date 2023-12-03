rule gost
{
    meta:
        description = "Detection patterns for the tool 'gost' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "gost"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Ransomware operators actively use Gost capabilities (<https://github.com/ginuerzh/gost>) in order to communicate with their remote server. using the command below. To hide the software in plain sight. they rename it to `System.exe` or `update.exe`.
        // Reference: https://github.com/ginuerzh/gost
        $string1 = /.{0,1000}C:\\Windows\\System\.exe.{0,1000}\s\-L\srtcp:\/\/0\.0\.0\.0:8087\/127\.0\.0\.1:4444\s\-F\ssocks5:\/\/.{0,1000}:.{0,1000}\@.{0,1000}:443.{0,1000}/ nocase ascii wide
        // Description: Ransomware operators actively use Gost capabilities (<https://github.com/ginuerzh/gost>) in order to communicate with their remote server. using the command below. To hide the software in plain sight. they rename it to `System.exe` or `update.exe`.
        // Reference: https://github.com/ginuerzh/gost
        $string2 = /.{0,1000}ginuerzh\/gost.{0,1000}/ nocase ascii wide
        // Description: Ransomware operators actively use Gost capabilities (<https://github.com/ginuerzh/gost>) in order to communicate with their remote server. using the command below. To hide the software in plain sight. they rename it to `System.exe` or `update.exe`.
        // Reference: https://github.com/ginuerzh/gost
        $string3 = /.{0,1000}gost\s\-L\=:.{0,1000}\s\-F\=.{0,1000}:.{0,1000}/ nocase ascii wide
        // Description: Ransomware operators actively use Gost capabilities (<https://github.com/ginuerzh/gost>) in order to communicate with their remote server. using the command below. To hide the software in plain sight. they rename it to `System.exe` or `update.exe`.
        // Reference: https://github.com/ginuerzh/gost
        $string4 = /.{0,1000}gost\s\-L\=admin:.{0,1000}\@localhost:.{0,1000}/ nocase ascii wide
        // Description: Ransomware operators actively use Gost capabilities (<https://github.com/ginuerzh/gost>) in order to communicate with their remote server. using the command below. To hide the software in plain sight. they rename it to `System.exe` or `update.exe`.
        // Reference: https://github.com/ginuerzh/gost
        $string5 = /.{0,1000}gost\s\-L\=forward\+ssh:\/\/:.{0,1000}/ nocase ascii wide
        // Description: Ransomware operators actively use Gost capabilities (<https://github.com/ginuerzh/gost>) in order to communicate with their remote server. using the command below. To hide the software in plain sight. they rename it to `System.exe` or `update.exe`.
        // Reference: https://github.com/ginuerzh/gost
        $string6 = /.{0,1000}gost\s\-L\=rtcp:\/\/.{0,1000}/ nocase ascii wide
        // Description: Ransomware operators actively use Gost capabilities (<https://github.com/ginuerzh/gost>) in order to communicate with their remote server. using the command below. To hide the software in plain sight. they rename it to `System.exe` or `update.exe`.
        // Reference: https://github.com/ginuerzh/gost
        $string7 = /.{0,1000}gost\s\-L\=rudp:\/\/.{0,1000}/ nocase ascii wide
        // Description: Ransomware operators actively use Gost capabilities (<https://github.com/ginuerzh/gost>) in order to communicate with their remote server. using the command below. To hide the software in plain sight. they rename it to `System.exe` or `update.exe`.
        // Reference: https://github.com/ginuerzh/gost
        $string8 = /.{0,1000}gost\s\-L\=ssh:\/\/:/ nocase ascii wide
        // Description: Ransomware operators actively use Gost capabilities (<https://github.com/ginuerzh/gost>) in order to communicate with their remote server. using the command below. To hide the software in plain sight. they rename it to `System.exe` or `update.exe`.
        // Reference: https://github.com/ginuerzh/gost
        $string9 = /.{0,1000}gost\s\-L\=ssu:\/\/.{0,1000}/ nocase ascii wide
        // Description: Ransomware operators actively use Gost capabilities (<https://github.com/ginuerzh/gost>) in order to communicate with their remote server. using the command below. To hide the software in plain sight. they rename it to `System.exe` or `update.exe`.
        // Reference: https://github.com/ginuerzh/gost
        $string10 = /.{0,1000}gost\s\-L\=udp:\/\/.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
