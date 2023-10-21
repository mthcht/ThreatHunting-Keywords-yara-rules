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
        $string1 = /\s\-t\s.*https:\/\/autodiscover\..*\/autodiscover\/autodiscover\.xml.*autodiscover/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string2 = /\s\-user\s.*\s\-\-passwordlist\s/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string3 = /\/ADFSpray/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string4 = /\\ADFSpray/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string5 = /ADFSpray\.csv/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string6 = /adfspray\.git/ nocase ascii wide
        // Description: Python3 tool to perform password spraying against Microsoft Online service using various methods
        // Reference: https://github.com/xFreed0m/ADFSpray
        $string7 = /ADFSpray\.py/ nocase ascii wide

    condition:
        any of them
}