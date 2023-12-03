rule undertheradar
{
    meta:
        description = "Detection patterns for the tool 'undertheradar' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "undertheradar"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: scripts that afford the pentester AV bypass techniques
        // Reference: https://github.com/g3tsyst3m/undertheradar
        $string1 = /.{0,1000}\.\\dumpy\.py.{0,1000}/ nocase ascii wide
        // Description: scripts that afford the pentester AV bypass techniques
        // Reference: https://github.com/g3tsyst3m/undertheradar
        $string2 = /.{0,1000}\/undertheradar\.git.{0,1000}/ nocase ascii wide
        // Description: scripts that afford the pentester AV bypass techniques
        // Reference: https://github.com/g3tsyst3m/undertheradar
        $string3 = /.{0,1000}\\public\\klogging\.log.{0,1000}/ nocase ascii wide
        // Description: scripts that afford the pentester AV bypass techniques
        // Reference: https://github.com/g3tsyst3m/undertheradar
        $string4 = /.{0,1000}\\users\\public\\sam\.save.{0,1000}/ nocase ascii wide
        // Description: scripts that afford the pentester AV bypass techniques
        // Reference: https://github.com/g3tsyst3m/undertheradar
        $string5 = /.{0,1000}\\users\\public\\system\.save.{0,1000}/ nocase ascii wide
        // Description: scripts that afford the pentester AV bypass techniques
        // Reference: https://github.com/g3tsyst3m/undertheradar
        $string6 = /.{0,1000}c:\/users\/public\/creds\.log.{0,1000}/ nocase ascii wide
        // Description: scripts that afford the pentester AV bypass techniques
        // Reference: https://github.com/g3tsyst3m/undertheradar
        $string7 = /.{0,1000}c:\\users\\public\\creds\.log.{0,1000}/ nocase ascii wide
        // Description: scripts that afford the pentester AV bypass techniques
        // Reference: https://github.com/g3tsyst3m/undertheradar
        $string8 = /.{0,1000}c:\\users\\public\\output\.txt.{0,1000}/ nocase ascii wide
        // Description: scripts that afford the pentester AV bypass techniques
        // Reference: https://github.com/g3tsyst3m/undertheradar
        $string9 = /.{0,1000}g3tsyst3m\/undertheradar.{0,1000}/ nocase ascii wide
        // Description: scripts that afford the pentester AV bypass techniques
        // Reference: https://github.com/g3tsyst3m/undertheradar
        $string10 = /.{0,1000}simplekeylogger\..{0,1000}/ nocase ascii wide
        // Description: scripts that afford the pentester AV bypass techniques
        // Reference: https://github.com/g3tsyst3m/undertheradar
        $string11 = /.{0,1000}Successfully\sdumped\sSAM\sand\sSYSTEM.{0,1000}/ nocase ascii wide
        // Description: scripts that afford the pentester AV bypass techniques
        // Reference: https://github.com/g3tsyst3m/undertheradar
        $string12 = /.{0,1000}undertheradar\-main.{0,1000}/ nocase ascii wide
        // Description: scripts that afford the pentester AV bypass techniques
        // Reference: https://github.com/g3tsyst3m/undertheradar
        $string13 = /.{0,1000}users\/public\/troubleshooting_log\.log.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
