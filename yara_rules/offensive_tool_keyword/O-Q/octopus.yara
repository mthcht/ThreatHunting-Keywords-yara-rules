rule octopus
{
    meta:
        description = "Detection patterns for the tool 'octopus' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "octopus"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string1 = /\sdeploy_cobalt_beacon/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string2 = /\soctopus\.py/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string3 = /\.\/.{0,1000}octopus\.py/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string4 = /\/agent\.ps1\.oct/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string5 = /\/octopus\.asm/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string6 = /\/Octopus\.git/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string7 = /\/octopusx64\.asm/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string8 = /\/weblistener\.py/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string9 = /ASBBypass\.ps1/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string10 = /generate_hta\soperation1/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string11 = /generate_powershell\soperation1/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string12 = /generate_spoofed_args_exe/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string13 = /generate_unmanaged_exe\soperation1\s.{0,1000}\.exe/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string14 = /generate_x64_shellcode/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string15 = /generate_x86_shellcode/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string16 = /ILBypass\.ps1/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string17 = /listen_http\s0\.0\.0\.0\s8080\s.{0,1000}\.php\soperation1/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string18 = /mhaskar\/Octopus/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string19 = /octopus\.py\s/ nocase ascii wide

    condition:
        any of them
}
