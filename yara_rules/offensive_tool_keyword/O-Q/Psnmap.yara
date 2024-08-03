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
        $string2 = /\/PSnmap\.ps1/ nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string3 = /\\PSnmap\.ps1/ nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string4 = /Add\-Member\s\-MemberType\sNoteProperty\s\-Name\sPing\s\-Value\s\(Test\-Connection\s\-ComputerName\s.{0,1000}\s\-Quiet\s\-Count\s1\)\s\-Force/ nocase ascii wide
        // Description: Powershell scanner (nmap like)
        // Reference: https://github.com/KurtDeGreeff/PlayPowershell/blob/master/PSnmap.ps1
        $string5 = /ba20280d3b1e1ba3539232ee1b32c6071958811da1cb6716aeb33480977da408/ nocase ascii wide

    condition:
        any of them
}
