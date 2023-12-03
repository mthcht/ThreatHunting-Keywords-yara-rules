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
        $string1 = /.{0,1000}\sdeploy_cobalt_beacon.{0,1000}/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string2 = /.{0,1000}\soctopus\.py.{0,1000}/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string3 = /.{0,1000}\.\/.{0,1000}octopus\.py.{0,1000}/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string4 = /.{0,1000}\/agent\.ps1\.oct.{0,1000}/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string5 = /.{0,1000}\/octopus\.asm.{0,1000}/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string6 = /.{0,1000}\/Octopus\.git.{0,1000}/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string7 = /.{0,1000}\/octopusx64\.asm.{0,1000}/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string8 = /.{0,1000}\/weblistener\.py.{0,1000}/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string9 = /.{0,1000}ASBBypass\.ps1.{0,1000}/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string10 = /.{0,1000}generate_hta\soperation1.{0,1000}/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string11 = /.{0,1000}generate_powershell\soperation1.{0,1000}/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string12 = /.{0,1000}generate_spoofed_args_exe.{0,1000}/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string13 = /.{0,1000}generate_unmanaged_exe\soperation1\s.{0,1000}\.exe/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string14 = /.{0,1000}generate_x64_shellcode.{0,1000}/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string15 = /.{0,1000}generate_x86_shellcode.{0,1000}/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string16 = /.{0,1000}ILBypass\.ps1.{0,1000}/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string17 = /.{0,1000}listen_http\s0\.0\.0\.0\s8080\s.{0,1000}\.php\soperation1.{0,1000}/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string18 = /.{0,1000}mhaskar\/Octopus.{0,1000}/ nocase ascii wide
        // Description: Octopus is an open source. pre-operation C2 server based on python which can control an Octopus powershell agent through HTTP/S.
        // Reference: https://github.com/mhaskar/Octopus
        $string19 = /.{0,1000}octopus\.py\s.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
