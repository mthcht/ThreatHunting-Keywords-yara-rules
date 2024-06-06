rule impacketremoteshell
{
    meta:
        description = "Detection patterns for the tool 'impacketremoteshell' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "impacketremoteshell"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string1 = /\sremoteshell\.py/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string2 = /\/RemoteMaintsvc\.exe/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string3 = /\/RemoteMaintsvc\.exe/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string4 = /\/remoteshell\.py/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string5 = /\\\\\.\\pipe\\RemoteMaint/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string6 = /\\\\\\\\\.\\\\pipe\\\\RemoteMaint/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string7 = /\\RemoteMaint\.sln/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string8 = /\\RemoteMaint\.vcxproj/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string9 = /\\RemoteMaintsvc\.exe/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string10 = /\\RemoteMaintsvc\.exe/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string11 = /\\remoteshell\.py/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string12 = /037f7348a66495d6502220e15f3766aa070dd12eb40b3d08d3f855c4cd77cf7f/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string13 = /11ef63b9bc33b0da6d0b5593e55e460aa8aa8279eb9ad4b90a4dc2b722ffa6e1/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string14 = /9e85c971331b8ad686c8d79ea81c4883d3f36a7de2071551fe5369fcf34ea3d0/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string15 = /CE23F388\-34F5\-4543\-81D1\-91CD244C9CB1/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string16 = /impacket\.internal_helpers/ nocase ascii wide
        // Description: install a legit application and interface with it over smb w/o the signature of cmd.exe / powershell.exe being called or the redirection typically used by those techniques
        // Reference: https://github.com/trustedsec/The_Shelf
        $string17 = /impacket\.smbconnection/ nocase ascii wide

    condition:
        any of them
}
