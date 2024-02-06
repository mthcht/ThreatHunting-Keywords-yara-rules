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
        $string1 = /\s\-DestHost\s.{0,1000}\s\-DestPort\s5555\s\-UseDefaultProxy/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string2 = /\/dbc2Loader/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string3 = /\/MailRaider\.ps1/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string4 = /\/oneliner\.tpl/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string5 = /\/oneliner2\.tpl/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string6 = /\/persist\.tpl/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string7 = /\/posh\.tpl/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string8 = /Arno0x\/DBC2/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string9 = /ConvertTo\-Shellcode\.ps1/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string10 = /DBC2\.git/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string11 = /dbc2_agent\.cs/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string12 = /dbc2_agent\.exe/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string13 = /dbc2Loader\.dll/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string14 = /dbc2Loader\.exe/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string15 = /dbc2Loader\.tpl/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string16 = /dbc2LoaderWrapperCLR\./ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string17 = /dbc2LoaderWrapperCLR_x64\.dll/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string18 = /dbc2LoaderWrapperCLR_x86\.dll/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string19 = /DBC2\-master\.zip/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string20 = /dnscat2\.ps1/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string21 = /dropboxC2\.py/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string22 = /Invoke\-Mimikatz\.ps1/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string23 = /Invoke\-NTLMAuth\.ps1/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string24 = /Invoke\-PowerDump/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string25 = /Invoke\-ReflectivePEInjection/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string26 = /Invoke\-SendMail\s\-Targets/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string27 = /Invoke\-SendReverseShell/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string28 = /Invoke\-Shellcode\s\-Shellcode/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string29 = /powercat\s\-c\s.{0,1000}\s\-p\s/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string30 = /powercat\s\-l\s\-p\s4444/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string31 = /Powercat\.ps1/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string32 = /powershell\.exe\s\-NoP\s\-sta\s\-NonI\s\-W\sHidden\s\-Command\s.{0,1000}Action\s\=\sNew\-ScheduledTaskAction\s\-Execute\s/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string33 = /PowerView\.ps1/ nocase ascii wide
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string34 = /regsvr32\.exe\s\/s\s\/n\s\/u\s\/i\:\s.{0,1000}\sscrobj\.dll/ nocase ascii wide

    condition:
        any of them
}
