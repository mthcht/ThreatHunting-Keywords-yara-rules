rule Psnmap
{
    meta:
        description = "Detection patterns for the tool 'Psnmap' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Psnmap"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string1 = /\sPSnmap\.ps1/ nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string2 = /\/PSnmap\.git/ nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string3 = /\/PSnmap\.ps1/ nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string4 = /\/PSnmap\.psd1/ nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string5 = /\/PSnmap\.psm1/ nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string6 = /\\PSnmap\.ps1/ nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string7 = /\\PSnmap\.psd1/ nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string8 = /\\PSnmap\.psm1/ nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string9 = "5e60bc27d24e7a5b641fa59ee55002dae44ce9dde494df9783a9aa002455c6d2" nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string10 = /Add\-Member\s\-MemberType\sNoteProperty\s\-Name\sPing\s\-Value\s\(Test\-Connection\s\-ComputerName\s.{0,1000}\s\-Quiet\s\-Count\s1\)\s\-Force/ nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string11 = "ba20280d3b1e1ba3539232ee1b32c6071958811da1cb6716aeb33480977da408" nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string12 = "be09f42e9225e82fe619a700b93d33e3bf0603266b7865d45a786630d4303aa7" nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string13 = "EliteLoser/PSnmap" nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string14 = "Install-Module -Name PSnmap -Scope " nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string15 = "Invoke-Psnmap" nocase ascii wide

    condition:
        any of them
}
