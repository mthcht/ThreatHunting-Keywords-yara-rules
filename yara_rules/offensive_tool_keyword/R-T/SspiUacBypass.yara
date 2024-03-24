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
        $string1 = /\s\-\sBypassing\sUAC\swith\sSSPI\sDatagram\sContexts/ nocase ascii wide
        // Description: Bypassing UAC with SSPI Datagram Contexts
        // Reference: https://github.com/antonioCoco/SspiUacBypass
        $string2 = /\sSspiUacBypass\s/ nocase ascii wide
        // Description: Bypassing UAC with SSPI Datagram Contexts
        // Reference: https://github.com/antonioCoco/SspiUacBypass
        $string3 = /\/SspiUacBypass\.git/ nocase ascii wide
        // Description: Bypassing UAC with SSPI Datagram Contexts
        // Reference: https://github.com/antonioCoco/SspiUacBypass
        $string4 = /\\bypassuac\.txt/ nocase ascii wide
        // Description: Bypassing UAC with SSPI Datagram Contexts
        // Reference: https://github.com/antonioCoco/SspiUacBypass
        $string5 = /5F4DC47F\-7819\-4528\-9C16\-C88F1BE97EC5/ nocase ascii wide
        // Description: Bypassing UAC with SSPI Datagram Contexts
        // Reference: https://github.com/antonioCoco/SspiUacBypass
        $string6 = /antonioCoco\/SspiUacBypass/ nocase ascii wide
        // Description: Bypassing UAC with SSPI Datagram Contexts
        // Reference: https://github.com/antonioCoco/SspiUacBypass
        $string7 = /Bypass\sSuccess\!\sNow\simpersonating\sthe\sforged\stoken.{0,1000}\sLoopback\snetwork\sauth\sshould\sbe\sseen\sas\selevated\snow/ nocase ascii wide
        // Description: Bypassing UAC with SSPI Datagram Contexts
        // Reference: https://github.com/antonioCoco/SspiUacBypass
        $string8 = /ea49111ee3bf716e9f4643f95b5df19fd8bd7376464b2795dcfc5e07ddda35eb/ nocase ascii wide
        // Description: Bypassing UAC with SSPI Datagram Contexts
        // Reference: https://github.com/antonioCoco/SspiUacBypass
        $string9 = /Forging\sa\stoken\sfrom\sa\sfake\sNetwork\sAuthentication\sthrough\sDatagram\sContexts/ nocase ascii wide
        // Description: Bypassing UAC with SSPI Datagram Contexts
        // Reference: https://github.com/antonioCoco/SspiUacBypass
        $string10 = /Invoking\sCreateSvcRpc\s\(by\s\@x86matthew/ nocase ascii wide
        // Description: Bypassing UAC with SSPI Datagram Contexts
        // Reference: https://github.com/antonioCoco/SspiUacBypass
        $string11 = /SspiUacBypass\.cpp/ nocase ascii wide
        // Description: Bypassing UAC with SSPI Datagram Contexts
        // Reference: https://github.com/antonioCoco/SspiUacBypass
        $string12 = /SspiUacBypass\.exe/ nocase ascii wide
        // Description: Bypassing UAC with SSPI Datagram Contexts
        // Reference: https://github.com/antonioCoco/SspiUacBypass
        $string13 = /SspiUacBypass\-main/ nocase ascii wide

    condition:
        any of them
}
