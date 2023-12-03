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
        $string1 = /.{0,1000}\.win10\.config\.fireeye.{0,1000}/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string2 = /.{0,1000}\.win7\.config\.fireeye.{0,1000}/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string3 = /.{0,1000}\/commando\-vm.{0,1000}/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string4 = /.{0,1000}choco\sinstall\s.{0,1000}\scommon\.fireeye.{0,1000}/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string5 = /.{0,1000}commandovm\..{0,1000}\.installer\.fireeye.{0,1000}/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string6 = /.{0,1000}commando\-vm\-master.{0,1000}/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string7 = /.{0,1000}\-ExecutionPolicy\sBypass\s\-File\sWin10\.ps1\s.{0,1000}/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string8 = /.{0,1000}\-ExecutionPolicy\sBypass\s\-File\sWin11\.ps1\s.{0,1000}/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string9 = /.{0,1000}fireeye.{0,1000}commando.{0,1000}/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string10 = /.{0,1000}https:\/\/www\.myget\.org\/F\/fireeye\/api\/v2.{0,1000}/ nocase ascii wide
        // Description: CommandoVM - a fully customizable Windows-based security distribution for penetration testing and red teaming.
        // Reference: https://github.com/mandiant/commando-vm
        $string11 = /.{0,1000}Unblock\-File\s\.\\install\.ps1.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
