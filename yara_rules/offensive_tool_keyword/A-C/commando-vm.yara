rule commando_vm
{
    meta:
        description = "Detection patterns for the tool 'commando-vm' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "commando-vm"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string1 = /\.win10\.config\.fireeye/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string2 = /\.win7\.config\.fireeye/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string3 = /\/commando\-vm/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string4 = /choco\sinstall\s.{0,1000}\scommon\.fireeye/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string5 = /cmd\.cat\/chattr/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string6 = /commandovm\..{0,1000}\.installer\.fireeye/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string7 = /commando\-vm\-master/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string8 = /\-ExecutionPolicy\sBypass\s\-File\sWin10\.ps1\s/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string9 = /\-ExecutionPolicy\sBypass\s\-File\sWin11\.ps1\s/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string10 = /fireeye.{0,1000}commando/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string11 = /https\:\/\/www\.myget\.org\/F\/fireeye\/api\/v2/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string12 = /Unblock\-File\s\.\\install\.ps1/ nocase ascii wide

    condition:
        any of them
}
