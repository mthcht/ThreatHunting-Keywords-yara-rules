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
        $string1 = /.{0,1000}\/Farmer\.git.{0,1000}/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string2 = /.{0,1000}\\Fertliser\.exe.{0,1000}/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string3 = /.{0,1000}\\Fertliser\.pdb.{0,1000}/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string4 = /.{0,1000}c:\\windows\\temp\\test\.tmp\sfarmer.{0,1000}/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string5 = /.{0,1000}crop\.exe\s\\\\.{0,1000}\\.{0,1000}\.lnk\s\\\\.{0,1000}\\harvest\s\\\\.{0,1000}\\harvest.{0,1000}/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string6 = /.{0,1000}farmer\.exe\s.{0,1000}\\windows\\temp.{0,1000}/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string7 = /.{0,1000}farmer\.exe\s8888\s60.{0,1000}/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string8 = /.{0,1000}Farmer\\Farmer\.csproj.{0,1000}/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string9 = /.{0,1000}Farmer\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string10 = /.{0,1000}Fertiliser\.exe\s\\\\.{0,1000}/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string11 = /.{0,1000}harvestcrop\.exe\s.{0,1000}\s.{0,1000}/ nocase ascii wide
        // Description: Farmer is a project for collecting NetNTLM hashes in a Windows domain. Farmer achieves this by creating a local WebDAV server that causes the WebDAV Mini Redirector to authenticate from any connecting clients.
        // Reference: https://github.com/mdsecactivebreach/Farmer
        $string12 = /.{0,1000}mdsecactivebreach\/Farmer.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
