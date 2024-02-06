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
        $string1 = /C\:\\Windows\\System\.exe.{0,1000}\s\-L\srtcp\:\/\/0\.0\.0\.0\:8087\/127\.0\.0\.1\:4444\s\-F\ssocks5\:\/\/.{0,1000}\:.{0,1000}\@.{0,1000}\:443/ nocase ascii wide
        // Description: Ransomware operators actively use Gost capabilities (<https://github.com/ginuerzh/gost>) in order to communicate with their remote server. using the command below. To hide the software in plain sight. they rename it to `System.exe` or `update.exe`.
        // Reference: https://github.com/ginuerzh/gost
        $string2 = /ginuerzh\/gost/ nocase ascii wide
        // Description: Ransomware operators actively use Gost capabilities (<https://github.com/ginuerzh/gost>) in order to communicate with their remote server. using the command below. To hide the software in plain sight. they rename it to `System.exe` or `update.exe`.
        // Reference: https://github.com/ginuerzh/gost
        $string3 = /gost\s\-L\=\:.{0,1000}\s\-F\=.{0,1000}\:/ nocase ascii wide
        // Description: Ransomware operators actively use Gost capabilities (<https://github.com/ginuerzh/gost>) in order to communicate with their remote server. using the command below. To hide the software in plain sight. they rename it to `System.exe` or `update.exe`.
        // Reference: https://github.com/ginuerzh/gost
        $string4 = /gost\s\-L\=admin\:.{0,1000}\@localhost\:/ nocase ascii wide
        // Description: Ransomware operators actively use Gost capabilities (<https://github.com/ginuerzh/gost>) in order to communicate with their remote server. using the command below. To hide the software in plain sight. they rename it to `System.exe` or `update.exe`.
        // Reference: https://github.com/ginuerzh/gost
        $string5 = /gost\s\-L\=forward\+ssh\:\/\/\:/ nocase ascii wide
        // Description: Ransomware operators actively use Gost capabilities (<https://github.com/ginuerzh/gost>) in order to communicate with their remote server. using the command below. To hide the software in plain sight. they rename it to `System.exe` or `update.exe`.
        // Reference: https://github.com/ginuerzh/gost
        $string6 = /gost\s\-L\=rtcp\:\/\// nocase ascii wide
        // Description: Ransomware operators actively use Gost capabilities (<https://github.com/ginuerzh/gost>) in order to communicate with their remote server. using the command below. To hide the software in plain sight. they rename it to `System.exe` or `update.exe`.
        // Reference: https://github.com/ginuerzh/gost
        $string7 = /gost\s\-L\=rudp\:\/\// nocase ascii wide
        // Description: Ransomware operators actively use Gost capabilities (<https://github.com/ginuerzh/gost>) in order to communicate with their remote server. using the command below. To hide the software in plain sight. they rename it to `System.exe` or `update.exe`.
        // Reference: https://github.com/ginuerzh/gost
        $string8 = /gost\s\-L\=ssh\:\/\/\:/ nocase ascii wide
        // Description: Ransomware operators actively use Gost capabilities (<https://github.com/ginuerzh/gost>) in order to communicate with their remote server. using the command below. To hide the software in plain sight. they rename it to `System.exe` or `update.exe`.
        // Reference: https://github.com/ginuerzh/gost
        $string9 = /gost\s\-L\=ssu\:\/\// nocase ascii wide
        // Description: Ransomware operators actively use Gost capabilities (<https://github.com/ginuerzh/gost>) in order to communicate with their remote server. using the command below. To hide the software in plain sight. they rename it to `System.exe` or `update.exe`.
        // Reference: https://github.com/ginuerzh/gost
        $string10 = /gost\s\-L\=udp\:\/\// nocase ascii wide

    condition:
        any of them
}
