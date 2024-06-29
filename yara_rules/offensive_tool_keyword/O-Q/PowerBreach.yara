rule PowerBreach
{
    meta:
        description = "Detection patterns for the tool 'PowerBreach' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerBreach"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PowerBreach is a backdoor toolkit that aims to provide the user a wide variety of methods to backdoor a system
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string1 = /\sPowerBreach\.ps1/ nocase ascii wide
        // Description: PowerBreach is a backdoor toolkit that aims to provide the user a wide variety of methods to backdoor a system
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string2 = /\!\!\!\sTHIS\sBACKDOOR\sREQUIRES\sFIREWALL\sEXCEPTION\s\!\!\!/ nocase ascii wide
        // Description: PowerBreach is a backdoor toolkit that aims to provide the user a wide variety of methods to backdoor a system
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string3 = /\/PowerBreach\.ps1/ nocase ascii wide
        // Description: PowerBreach is a backdoor toolkit that aims to provide the user a wide variety of methods to backdoor a system
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string4 = /\\PowerBreach\.ps1/ nocase ascii wide
        // Description: PowerBreach is a backdoor toolkit that aims to provide the user a wide variety of methods to backdoor a system
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string5 = /4808ad1202bb14375f19929cb389433ffca4b27eaba4490da262a48f57b5af64/ nocase ascii wide
        // Description: PowerBreach is a backdoor toolkit that aims to provide the user a wide variety of methods to backdoor a system
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string6 = /6ce500821488255bc70acd310d8162308fd14a4fa214c79c2d9a354c705de6d7/ nocase ascii wide
        // Description: PowerBreach is a backdoor toolkit that aims to provide the user a wide variety of methods to backdoor a system
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string7 = /Add\-PSFirewallRules/ nocase ascii wide
        // Description: PowerBreach is a backdoor toolkit that aims to provide the user a wide variety of methods to backdoor a system
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string8 = /Invoke\-CallbackIEX/ nocase ascii wide
        // Description: PowerBreach is a backdoor toolkit that aims to provide the user a wide variety of methods to backdoor a system
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string9 = /Invoke\-DeadUserBackdoor/ nocase ascii wide
        // Description: PowerBreach is a backdoor toolkit that aims to provide the user a wide variety of methods to backdoor a system
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string10 = /Invoke\-EventLogBackdoor/ nocase ascii wide
        // Description: PowerBreach is a backdoor toolkit that aims to provide the user a wide variety of methods to backdoor a system
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string11 = /Invoke\-LoopBackdoor/ nocase ascii wide
        // Description: PowerBreach is a backdoor toolkit that aims to provide the user a wide variety of methods to backdoor a system
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string12 = /Invoke\-PortBindBackdoor/ nocase ascii wide
        // Description: PowerBreach is a backdoor toolkit that aims to provide the user a wide variety of methods to backdoor a system
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string13 = /Invoke\-PortKnockBackdoor/ nocase ascii wide
        // Description: PowerBreach is a backdoor toolkit that aims to provide the user a wide variety of methods to backdoor a system
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string14 = /Invoke\-ResolverBackdoor/ nocase ascii wide
        // Description: PowerBreach is a backdoor toolkit that aims to provide the user a wide variety of methods to backdoor a system
        // Reference: https://github.com/PowerShellEmpire/PowerTools
        $string15 = /This\sbackdoor\srequires\sAdmin\s\:\(/ nocase ascii wide

    condition:
        any of them
}
