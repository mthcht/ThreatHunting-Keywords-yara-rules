rule SspiUacBypass
{
    meta:
        description = "Detection patterns for the tool 'SspiUacBypass' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SspiUacBypass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Bypassing UAC with SSPI Datagram Contexts
        // Reference: https://github.com/antonioCoco/SspiUacBypass
        $string1 = /.{0,1000}\sSspiUacBypass\s.{0,1000}/ nocase ascii wide
        // Description: Bypassing UAC with SSPI Datagram Contexts
        // Reference: https://github.com/antonioCoco/SspiUacBypass
        $string2 = /.{0,1000}\/SspiUacBypass\.git.{0,1000}/ nocase ascii wide
        // Description: Bypassing UAC with SSPI Datagram Contexts
        // Reference: https://github.com/antonioCoco/SspiUacBypass
        $string3 = /.{0,1000}\\bypassuac\.txt.{0,1000}/ nocase ascii wide
        // Description: Bypassing UAC with SSPI Datagram Contexts
        // Reference: https://github.com/antonioCoco/SspiUacBypass
        $string4 = /.{0,1000}5F4DC47F\-7819\-4528\-9C16\-C88F1BE97EC5.{0,1000}/ nocase ascii wide
        // Description: Bypassing UAC with SSPI Datagram Contexts
        // Reference: https://github.com/antonioCoco/SspiUacBypass
        $string5 = /.{0,1000}antonioCoco\/SspiUacBypass.{0,1000}/ nocase ascii wide
        // Description: Bypassing UAC with SSPI Datagram Contexts
        // Reference: https://github.com/antonioCoco/SspiUacBypass
        $string6 = /.{0,1000}Invoking\sCreateSvcRpc\s\(by\s\@x86matthew.{0,1000}/ nocase ascii wide
        // Description: Bypassing UAC with SSPI Datagram Contexts
        // Reference: https://github.com/antonioCoco/SspiUacBypass
        $string7 = /.{0,1000}SspiUacBypass\.cpp.{0,1000}/ nocase ascii wide
        // Description: Bypassing UAC with SSPI Datagram Contexts
        // Reference: https://github.com/antonioCoco/SspiUacBypass
        $string8 = /.{0,1000}SspiUacBypass\.exe.{0,1000}/ nocase ascii wide
        // Description: Bypassing UAC with SSPI Datagram Contexts
        // Reference: https://github.com/antonioCoco/SspiUacBypass
        $string9 = /.{0,1000}SspiUacBypass\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
