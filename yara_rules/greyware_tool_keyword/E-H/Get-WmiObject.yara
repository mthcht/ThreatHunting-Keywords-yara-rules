rule Get_WmiObject
{
    meta:
        description = "Detection patterns for the tool 'Get-WmiObject' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Get-WmiObject"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Get logged on user on remote host with Get-WmiObject
        // Reference: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1
        $string1 = /Get\-WmiObject\s\?ComputerName\s.{0,1000}\s\?Class\sWin32_ComputerSystem\s\|\s.{0,1000}\sUserName/ nocase ascii wide
        // Description: Get SCCM server with Get-WmiObject
        // Reference: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1
        $string2 = /Get\-WmiObject\s\-class\sSMS_Authority\s\-namespace\sroot\\CCM/ nocase ascii wide
        // Description: Get logged on user on remote host with Get-WmiObject
        // Reference: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1
        $string3 = /Get\-WmiObject\swin32_loggedonuser\s\-ComputerName\s/ nocase ascii wide

    condition:
        any of them
}
