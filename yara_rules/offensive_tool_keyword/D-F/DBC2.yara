rule DBC2
{
    meta:
        description = "Detection patterns for the tool 'DBC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DBC2"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string1 = /.{0,1000}\s\-DestHost\s.{0,1000}\s\-DestPort\s5555\s\-UseDefaultProxy.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string2 = /.{0,1000}\/dbc2Loader.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string3 = /.{0,1000}\/MailRaider\.ps1.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string4 = /.{0,1000}\/oneliner\.tpl.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string5 = /.{0,1000}\/oneliner2\.tpl.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string6 = /.{0,1000}\/persist\.tpl.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string7 = /.{0,1000}\/posh\.tpl.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string8 = /.{0,1000}Arno0x\/DBC2.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string9 = /.{0,1000}ConvertTo\-Shellcode\.ps1.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string10 = /.{0,1000}DBC2\.git.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string11 = /.{0,1000}dbc2_agent\.cs.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string12 = /.{0,1000}dbc2_agent\.exe.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string13 = /.{0,1000}dbc2Loader\.dll.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string14 = /.{0,1000}dbc2Loader\.exe.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string15 = /.{0,1000}dbc2Loader\.tpl.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string16 = /.{0,1000}dbc2LoaderWrapperCLR\..{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string17 = /.{0,1000}dbc2LoaderWrapperCLR_x64\.dll.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string18 = /.{0,1000}dbc2LoaderWrapperCLR_x86\.dll.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string19 = /.{0,1000}DBC2\-master\.zip.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string20 = /.{0,1000}dnscat2\.ps1.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string21 = /.{0,1000}dropboxC2\.py.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string22 = /.{0,1000}Invoke\-Mimikatz\.ps1.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string23 = /.{0,1000}Invoke\-NTLMAuth\.ps1.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string24 = /.{0,1000}Invoke\-PowerDump.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string25 = /.{0,1000}Invoke\-ReflectivePEInjection.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string26 = /.{0,1000}Invoke\-SendMail\s\-Targets.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string27 = /.{0,1000}Invoke\-SendReverseShell.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string28 = /.{0,1000}Invoke\-Shellcode\s\-Shellcode.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string29 = /.{0,1000}powercat\s\-c\s.{0,1000}\s\-p\s.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string30 = /.{0,1000}powercat\s\-l\s\-p\s4444.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string31 = /.{0,1000}Powercat\.ps1.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string32 = /.{0,1000}powershell\.exe\s\-NoP\s\-sta\s\-NonI\s\-W\sHidden\s\-Command\s.{0,1000}Action\s\=\sNew\-ScheduledTaskAction\s\-Execute\s.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string33 = /.{0,1000}PowerView\.ps1.{0,1000}/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string34 = /.{0,1000}regsvr32\.exe\s\/s\s\/n\s\/u\s\/i:\s.{0,1000}\sscrobj\.dll.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
