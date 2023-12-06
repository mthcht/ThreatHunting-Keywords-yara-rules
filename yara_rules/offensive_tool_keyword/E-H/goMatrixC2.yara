rule goMatrixC2
{
    meta:
        description = "Detection patterns for the tool 'goMatrixC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "goMatrixC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: C2 leveraging Matrix/Element Messaging Platform as Backend to control Implants in goLang.
        // Reference: https://github.com/n1k7l4i/goMatrixC2
        $string1 = /\/AntiSandbox\.go/ nocase ascii wide
        // Description: C2 leveraging Matrix/Element Messaging Platform as Backend to control Implants in goLang.
        // Reference: https://github.com/n1k7l4i/goMatrixC2
        $string2 = /\/goMatrixC2\.git/ nocase ascii wide
        // Description: C2 leveraging Matrix/Element Messaging Platform as Backend to control Implants in goLang.
        // Reference: https://github.com/n1k7l4i/goMatrixC2
        $string3 = /\\AntiSandbox\.go/ nocase ascii wide
        // Description: C2 leveraging Matrix/Element Messaging Platform as Backend to control Implants in goLang.
        // Reference: https://github.com/n1k7l4i/goMatrixC2
        $string4 = /goMatrixC2\.go/ nocase ascii wide
        // Description: C2 leveraging Matrix/Element Messaging Platform as Backend to control Implants in goLang.
        // Reference: https://github.com/n1k7l4i/goMatrixC2
        $string5 = /goMatrixC2\-main/ nocase ascii wide
        // Description: C2 leveraging Matrix/Element Messaging Platform as Backend to control Implants in goLang.
        // Reference: https://github.com/n1k7l4i/goMatrixC2
        $string6 = /n1k7l4i\/goMatrixC2/ nocase ascii wide

    condition:
        any of them
}
