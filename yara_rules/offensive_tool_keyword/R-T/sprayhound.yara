rule sprayhound
{
    meta:
        description = "Detection patterns for the tool 'sprayhound' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sprayhound"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Password spraying tool and Bloodhound integration
        // Reference: https://github.com/Hackndo/sprayhound
        $string1 = /.{0,1000}\s\-\-neo4j\-host\s.{0,1000}\-\-neo4j\-port.{0,1000}/ nocase ascii wide
        // Description: Password spraying tool and Bloodhound integration
        // Reference: https://github.com/Hackndo/sprayhound
        $string2 = /.{0,1000}\/sprayhound\.git.{0,1000}/ nocase ascii wide
        // Description: Password spraying tool and Bloodhound integration
        // Reference: https://github.com/Hackndo/sprayhound
        $string3 = /.{0,1000}\/sprayhound\/.{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: Password spraying tool and Bloodhound integration
        // Reference: https://github.com/Hackndo/sprayhound
        $string4 = /.{0,1000}Hackndo\/sprayhound.{0,1000}/ nocase ascii wide
        // Description: Password spraying tool and Bloodhound integration
        // Reference: https://github.com/Hackndo/sprayhound
        $string5 = /.{0,1000}neo4jconnection\.py.{0,1000}/ nocase ascii wide
        // Description: Password spraying tool and Bloodhound integration
        // Reference: https://github.com/Hackndo/sprayhound
        $string6 = /.{0,1000}\-nh\s127\.0\.0\.1\s\-nP\s7687\s\-nu\sneo4j\s\-np\s.{0,1000}/ nocase ascii wide
        // Description: Password spraying tool and Bloodhound integration
        // Reference: https://github.com/Hackndo/sprayhound
        $string7 = /.{0,1000}sprayhound\s\-.{0,1000}/ nocase ascii wide
        // Description: Password spraying tool and Bloodhound integration
        // Reference: https://github.com/Hackndo/sprayhound
        $string8 = /.{0,1000}sprayhound\-master\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
