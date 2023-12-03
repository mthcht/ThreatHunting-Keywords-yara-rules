rule SeeYouCM_Thief
{
    meta:
        description = "Detection patterns for the tool 'SeeYouCM-Thief' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SeeYouCM-Thief"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string1 = /.{0,1000}\sthief\.py.{0,1000}/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string2 = /.{0,1000}\/SeeYouCM\-Thief.{0,1000}/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string3 = /.{0,1000}\/thief\.py.{0,1000}/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string4 = /.{0,1000}cisco\-phone\-query\.sh.{0,1000}/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string5 = /.{0,1000}Credentials\sFound\sin\sConfigurations\!.{0,1000}/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string6 = /.{0,1000}python.{0,1000}http:\/\/.{0,1000}:6970\/ConfigFileCacheList\.txt.{0,1000}/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string7 = /.{0,1000}python.{0,1000}\'http:\/\/.{0,1000}SEP.{0,1000}:6970\/.{0,1000}\.cnf\.xml.{0,1000}/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string8 = /.{0,1000}python.{0,1000}https:\/\/.{0,1000}:8443\/cucm\-uds\/users\?name\=.{0,1000}/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string9 = /.{0,1000}run\sthief:latest.{0,1000}/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string10 = /.{0,1000}search_for_secrets\(.{0,1000}/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string11 = /.{0,1000}SeeYouCM\-Thief\.git.{0,1000}/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string12 = /.{0,1000}SeeYouCM\-Thief\-main.{0,1000}/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string13 = /.{0,1000}thief\.py\s\-.{0,1000}/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string14 = /.{0,1000}tmp.{0,1000}ciscophones\.tgz.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
