rule adfspray
{
    meta:
        description = "Detection patterns for the tool 'adfspray' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "adfspray"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string1 = /\s\-t\s.{0,1000}https\:\/\/autodiscover\..{0,1000}\/autodiscover\/autodiscover\.xml.{0,1000}autodiscover/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string2 = /\s\-user\s.{0,1000}\s\-\-passwordlist\s/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string3 = /\/ADFSpray/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string4 = /\[.{0,1000}\]\sOverall\scompromised\saccounts\:\s/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string5 = /\[\+\]\sSeems\slike\sthe\screds\sare\svalid\:\s.{0,1000}\s\:\:\s.{0,1000}\son\s/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string6 = /\\ADFSpray/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string7 = /ADFSpray\.csv/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string8 = /adfspray\.git/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string9 = /ADFSpray\.py/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string10 = /Total\snumber\sof\spasswords\sto\stest\:\s/ nocase ascii wide

    condition:
        any of them
}
