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
        $string1 = /.{0,1000}\s\-t\s.{0,1000}https:\/\/autodiscover\..{0,1000}\/autodiscover\/autodiscover\.xml.{0,1000}autodiscover.{0,1000}/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string2 = /.{0,1000}\s\-user\s.{0,1000}\s\-\-passwordlist\s.{0,1000}/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string3 = /.{0,1000}\/ADFSpray.{0,1000}/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string4 = /.{0,1000}\[.{0,1000}\]\sOverall\scompromised\saccounts:\s.{0,1000}/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string5 = /.{0,1000}\[\+\]\sSeems\slike\sthe\screds\sare\svalid:\s.{0,1000}\s::\s.{0,1000}\son\s.{0,1000}/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string6 = /.{0,1000}\\ADFSpray.{0,1000}/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string7 = /.{0,1000}ADFSpray\.csv.{0,1000}/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string8 = /.{0,1000}adfspray\.git.{0,1000}/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string9 = /.{0,1000}ADFSpray\.py.{0,1000}/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string10 = /.{0,1000}Total\snumber\sof\spasswords\sto\stest:\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
