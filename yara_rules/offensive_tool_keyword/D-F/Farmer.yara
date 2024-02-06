rule Farmer
{
    meta:
        description = "Detection patterns for the tool 'Farmer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Farmer"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string1 = /\/Farmer\.git/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string2 = /\\Fertliser\.exe/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string3 = /\\Fertliser\.pdb/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string4 = /c\:\\windows\\temp\\test\.tmp\sfarmer/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string5 = /crop\.exe\s\\\\.{0,1000}\\.{0,1000}\.lnk\s\\\\.{0,1000}\\harvest\s\\\\.{0,1000}\\harvest/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string6 = /farmer\.exe\s.{0,1000}\\windows\\temp/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string7 = /farmer\.exe\s8888\s60/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string8 = /Farmer\\Farmer\.csproj/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string9 = /Farmer\-main\.zip/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string10 = /Fertiliser\.exe\s\\\\/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string11 = /harvestcrop\.exe\s.{0,1000}\s/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string12 = /mdsecactivebreach\/Farmer/ nocase ascii wide

    condition:
        any of them
}
