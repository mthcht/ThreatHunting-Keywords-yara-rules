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
        $string1 = /.{0,1000}\/AntiSandbox\.go.{0,1000}/ nocase ascii wide
        // Description: C2 leveraging Matrix/Element Messaging Platform as Backend to control Implants in goLang.
        // Reference: https://github.com/n1k7l4i/goMatrixC2
        $string2 = /.{0,1000}\/goMatrixC2\.git.{0,1000}/ nocase ascii wide
        // Description: C2 leveraging Matrix/Element Messaging Platform as Backend to control Implants in goLang.
        // Reference: https://github.com/n1k7l4i/goMatrixC2
        $string3 = /.{0,1000}\\AntiSandbox\.go.{0,1000}/ nocase ascii wide
        // Description: C2 leveraging Matrix/Element Messaging Platform as Backend to control Implants in goLang.
        // Reference: https://github.com/n1k7l4i/goMatrixC2
        $string4 = /.{0,1000}goMatrixC2\.go.{0,1000}/ nocase ascii wide
        // Description: C2 leveraging Matrix/Element Messaging Platform as Backend to control Implants in goLang.
        // Reference: https://github.com/n1k7l4i/goMatrixC2
        $string5 = /.{0,1000}goMatrixC2\-main.{0,1000}/ nocase ascii wide
        // Description: C2 leveraging Matrix/Element Messaging Platform as Backend to control Implants in goLang.
        // Reference: https://github.com/n1k7l4i/goMatrixC2
        $string6 = /.{0,1000}n1k7l4i\/goMatrixC2.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
