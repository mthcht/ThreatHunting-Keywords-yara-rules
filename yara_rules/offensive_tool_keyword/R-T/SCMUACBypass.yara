rule SCMUACBypass
{
    meta:
        description = "Detection patterns for the tool 'SCMUACBypass' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SCMUACBypass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SCM UAC Bypass
        // Reference: https://github.com/rasta-mouse/SCMUACBypass
        $string1 = /.{0,1000}\sscmuacbypass\.cpp.{0,1000}/ nocase ascii wide
        // Description: SCM UAC Bypass
        // Reference: https://github.com/rasta-mouse/SCMUACBypass
        $string2 = /.{0,1000}\sscmuacbypass\.exe.{0,1000}/ nocase ascii wide
        // Description: SCM UAC Bypass
        // Reference: https://github.com/rasta-mouse/SCMUACBypass
        $string3 = /.{0,1000}\/scmuacbypass\.cpp.{0,1000}/ nocase ascii wide
        // Description: SCM UAC Bypass
        // Reference: https://github.com/rasta-mouse/SCMUACBypass
        $string4 = /.{0,1000}\/scmuacbypass\.exe.{0,1000}/ nocase ascii wide
        // Description: SCM UAC Bypass
        // Reference: https://github.com/rasta-mouse/SCMUACBypass
        $string5 = /.{0,1000}\/SCMUACBypass\.git.{0,1000}/ nocase ascii wide
        // Description: SCM UAC Bypass
        // Reference: https://github.com/rasta-mouse/SCMUACBypass
        $string6 = /.{0,1000}\/SCMUACBypass\/.{0,1000}/ nocase ascii wide
        // Description: SCM UAC Bypass
        // Reference: https://github.com/rasta-mouse/SCMUACBypass
        $string7 = /.{0,1000}\\scmuacbypass\.cpp.{0,1000}/ nocase ascii wide
        // Description: SCM UAC Bypass
        // Reference: https://github.com/rasta-mouse/SCMUACBypass
        $string8 = /.{0,1000}\\scmuacbypass\.exe.{0,1000}/ nocase ascii wide
        // Description: SCM UAC Bypass
        // Reference: https://github.com/rasta-mouse/SCMUACBypass
        $string9 = /.{0,1000}\\SCMUACBypass\\.{0,1000}/ nocase ascii wide
        // Description: SCM UAC Bypass
        // Reference: https://github.com/rasta-mouse/SCMUACBypass
        $string10 = /.{0,1000}UACBypassedService\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
