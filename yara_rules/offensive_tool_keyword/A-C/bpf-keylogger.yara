rule bpf_keylogger
{
    meta:
        description = "Detection patterns for the tool 'bpf-keylogger' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bpf-keylogger"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Keylogger written in BPF
        // Reference: https://github.com/SkyperTHC/bpf-keylogger
        $string1 = /\(prog\=\"bpf\-keylogger\"/ nocase ascii wide
        // Description: Keylogger written in BPF
        // Reference: https://github.com/SkyperTHC/bpf-keylogger
        $string2 = /\/bpf\-keylogger\.git/ nocase ascii wide
        // Description: Keylogger written in BPF
        // Reference: https://github.com/SkyperTHC/bpf-keylogger
        $string3 = /\/bpf\-keylogger\// nocase ascii wide
        // Description: Keylogger written in BPF
        // Reference: https://github.com/SkyperTHC/bpf-keylogger
        $string4 = /A\skeylogger\swritten\sin\seBPF\./ nocase ascii wide
        // Description: Keylogger written in BPF
        // Reference: https://github.com/SkyperTHC/bpf-keylogger
        $string5 = /bpf_keylogger\:\sLog\skey\spresses\sand\smouse\sbutton\sevents\ssystemwide\susing\seBPF/ nocase ascii wide
        // Description: Keylogger written in BPF
        // Reference: https://github.com/SkyperTHC/bpf-keylogger
        $string6 = /Logging\skey\spresses\.\.\.\sctrl\-c\sto\squit/ nocase ascii wide
        // Description: Keylogger written in BPF
        // Reference: https://github.com/SkyperTHC/bpf-keylogger
        $string7 = /SkyperTHC\/bpf\-keylogger/ nocase ascii wide
        // Description: Keylogger written in BPF
        // Reference: https://github.com/willfindlay/bpf-keylogger
        $string8 = /willfindlay\/bpf\-keylogger/ nocase ascii wide

    condition:
        any of them
}
