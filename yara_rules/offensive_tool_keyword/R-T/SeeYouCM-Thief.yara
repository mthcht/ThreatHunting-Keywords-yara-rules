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
        $string1 = /\sthief\.py/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string2 = /\/SeeYouCM\-Thief/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string3 = /\/thief\.py/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string4 = /cisco\-phone\-query\.sh/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string5 = /Credentials\sFound\sin\sConfigurations\!/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string6 = /python.{0,1000}http\:\/\/.{0,1000}\:6970\/ConfigFileCacheList\.txt/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string7 = /python.{0,1000}\'http\:\/\/.{0,1000}SEP.{0,1000}\:6970\/.{0,1000}\.cnf\.xml/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string8 = /python.{0,1000}https\:\/\/.{0,1000}\:8443\/cucm\-uds\/users\?name\=/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string9 = /run\sthief\:latest/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string10 = /search_for_secrets\(/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string11 = /SeeYouCM\-Thief\.git/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string12 = /SeeYouCM\-Thief\-main/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string13 = /thief\.py\s\-/ nocase ascii wide
        // Description: Simple tool to automatically download and parse configuration files from Cisco phone systems searching for SSH credentials
        // Reference: https://github.com/trustedsec/SeeYouCM-Thief
        $string14 = /tmp.{0,1000}ciscophones\.tgz/ nocase ascii wide

    condition:
        any of them
}
