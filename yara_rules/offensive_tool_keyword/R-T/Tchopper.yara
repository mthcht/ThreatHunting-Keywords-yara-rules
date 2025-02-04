rule Tchopper
{
    meta:
        description = "Detection patterns for the tool 'Tchopper' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Tchopper"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string1 = /\stmp_payload\.txt/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string2 = "#1 - Smuggling binary via Service DisplayName" nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string3 = "#2 - Smuggling binary via WMI" nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string4 = /\/TChopper\.git/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string5 = /\[\+\]\stask\shas\sbeen\screated\ssuccessfully\s\s\.\.\!/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string6 = /\[\-\>\]\ssending\spayload\.\.as\schuncks/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string7 = /\\Public\\chop\.enc/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string8 = /\\TChopper\\chopper\./ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string9 = /\\Tchopper\-main\.zip/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string10 = /\\tmp_payload\.txt/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string11 = "chop target username password domain filename chd wmi" nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string12 = /chopper\.exe\s\-m/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string13 = /chopper\.exe\s\-s/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string14 = /chopper\.exe\s\-w/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string15 = /cmd\.exe\s\/c\spowershell\s\-command\s\\"Get\-Service\s.{0,1000}chopper/ nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string16 = "Data Name=\"ServiceName\">chopper</Data>" nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string17 = "Data Name=\"ServiceName\">final_seg</Data>" nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string18 = "Data Name=\"ServiceName\">let me in</Data>" nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string19 = "lawrenceamer/Tchopper" nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string20 = "'svc_smuggling'" nocase ascii wide
        // Description: conduct Lateral Movement attack by leveraging unfiltered services display name to smuggle binaries as chunks into the target machine
        // Reference: https://github.com/lawrenceamer/Tchopper
        $string21 = "Technique #1 - Chop Chop - Create/delete" nocase ascii wide

    condition:
        any of them
}
