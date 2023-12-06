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
        $string1 = /\sscmuacbypass\.cpp/ nocase ascii wide
        // Description: SCM UAC Bypass
        // Reference: https://github.com/rasta-mouse/SCMUACBypass
        $string2 = /\sscmuacbypass\.exe/ nocase ascii wide
        // Description: SCM UAC Bypass
        // Reference: https://github.com/rasta-mouse/SCMUACBypass
        $string3 = /\/scmuacbypass\.cpp/ nocase ascii wide
        // Description: SCM UAC Bypass
        // Reference: https://github.com/rasta-mouse/SCMUACBypass
        $string4 = /\/scmuacbypass\.exe/ nocase ascii wide
        // Description: SCM UAC Bypass
        // Reference: https://github.com/rasta-mouse/SCMUACBypass
        $string5 = /\/SCMUACBypass\.git/ nocase ascii wide
        // Description: SCM UAC Bypass
        // Reference: https://github.com/rasta-mouse/SCMUACBypass
        $string6 = /\/SCMUACBypass\// nocase ascii wide
        // Description: SCM UAC Bypass
        // Reference: https://github.com/rasta-mouse/SCMUACBypass
        $string7 = /\\scmuacbypass\.cpp/ nocase ascii wide
        // Description: SCM UAC Bypass
        // Reference: https://github.com/rasta-mouse/SCMUACBypass
        $string8 = /\\scmuacbypass\.exe/ nocase ascii wide
        // Description: SCM UAC Bypass
        // Reference: https://github.com/rasta-mouse/SCMUACBypass
        $string9 = /\\SCMUACBypass\\/ nocase ascii wide
        // Description: SCM UAC Bypass
        // Reference: https://github.com/rasta-mouse/SCMUACBypass
        $string10 = /UACBypassedService\.exe/ nocase ascii wide

    condition:
        any of them
}
