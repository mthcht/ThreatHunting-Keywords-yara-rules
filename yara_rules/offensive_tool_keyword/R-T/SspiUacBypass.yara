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
        $string1 = /\sSspiUacBypass\s/ nocase ascii wide
        // Description: Bypassing UAC with SSPI Datagram Contexts
        // Reference: https://github.com/antonioCoco/SspiUacBypass
        $string2 = /\/SspiUacBypass\.git/ nocase ascii wide
        // Description: Bypassing UAC with SSPI Datagram Contexts
        // Reference: https://github.com/antonioCoco/SspiUacBypass
        $string3 = /\\bypassuac\.txt/ nocase ascii wide
        // Description: Bypassing UAC with SSPI Datagram Contexts
        // Reference: https://github.com/antonioCoco/SspiUacBypass
        $string4 = /5F4DC47F\-7819\-4528\-9C16\-C88F1BE97EC5/ nocase ascii wide
        // Description: Bypassing UAC with SSPI Datagram Contexts
        // Reference: https://github.com/antonioCoco/SspiUacBypass
        $string5 = /antonioCoco\/SspiUacBypass/ nocase ascii wide
        // Description: Bypassing UAC with SSPI Datagram Contexts
        // Reference: https://github.com/antonioCoco/SspiUacBypass
        $string6 = /Invoking\sCreateSvcRpc\s\(by\s\@x86matthew/ nocase ascii wide
        // Description: Bypassing UAC with SSPI Datagram Contexts
        // Reference: https://github.com/antonioCoco/SspiUacBypass
        $string7 = /SspiUacBypass\.cpp/ nocase ascii wide
        // Description: Bypassing UAC with SSPI Datagram Contexts
        // Reference: https://github.com/antonioCoco/SspiUacBypass
        $string8 = /SspiUacBypass\.exe/ nocase ascii wide
        // Description: Bypassing UAC with SSPI Datagram Contexts
        // Reference: https://github.com/antonioCoco/SspiUacBypass
        $string9 = /SspiUacBypass\-main/ nocase ascii wide

    condition:
        any of them
}