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
        $string1 = /\.\\dumpy\.py/ nocase ascii wide
        // Description: scripts that afford the pentester AV bypass techniques
        // Reference: https://github.com/g3tsyst3m/undertheradar
        $string2 = /\/undertheradar\.git/ nocase ascii wide
        // Description: scripts that afford the pentester AV bypass techniques
        // Reference: https://github.com/g3tsyst3m/undertheradar
        $string3 = /\\public\\klogging\.log/ nocase ascii wide
        // Description: scripts that afford the pentester AV bypass techniques
        // Reference: https://github.com/g3tsyst3m/undertheradar
        $string4 = /\\users\\public\\sam\.save/ nocase ascii wide
        // Description: scripts that afford the pentester AV bypass techniques
        // Reference: https://github.com/g3tsyst3m/undertheradar
        $string5 = /\\users\\public\\system\.save/ nocase ascii wide
        // Description: scripts that afford the pentester AV bypass techniques
        // Reference: https://github.com/g3tsyst3m/undertheradar
        $string6 = /c\:\/users\/public\/creds\.log/ nocase ascii wide
        // Description: scripts that afford the pentester AV bypass techniques
        // Reference: https://github.com/g3tsyst3m/undertheradar
        $string7 = /c\:\\users\\public\\creds\.log/ nocase ascii wide
        // Description: scripts that afford the pentester AV bypass techniques
        // Reference: https://github.com/g3tsyst3m/undertheradar
        $string8 = /c\:\\users\\public\\output\.txt/ nocase ascii wide
        // Description: scripts that afford the pentester AV bypass techniques
        // Reference: https://github.com/g3tsyst3m/undertheradar
        $string9 = /g3tsyst3m\/undertheradar/ nocase ascii wide
        // Description: scripts that afford the pentester AV bypass techniques
        // Reference: https://github.com/g3tsyst3m/undertheradar
        $string10 = /simplekeylogger\./ nocase ascii wide
        // Description: scripts that afford the pentester AV bypass techniques
        // Reference: https://github.com/g3tsyst3m/undertheradar
        $string11 = /Successfully\sdumped\sSAM\sand\sSYSTEM/ nocase ascii wide
        // Description: scripts that afford the pentester AV bypass techniques
        // Reference: https://github.com/g3tsyst3m/undertheradar
        $string12 = /undertheradar\-main/ nocase ascii wide
        // Description: scripts that afford the pentester AV bypass techniques
        // Reference: https://github.com/g3tsyst3m/undertheradar
        $string13 = /users\/public\/troubleshooting_log\.log/ nocase ascii wide

    condition:
        any of them
}
