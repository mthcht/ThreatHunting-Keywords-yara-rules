rule DBC2
{
    meta:
        description = "Detection patterns for the tool 'DBC2' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DBC2"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: DBC2 (DropboxC2) is a modular post-exploitation tool composed of an agent running on the victim's machine - a controler running on any machine - powershell modules and Dropbox servers as a means of communication.
        // Reference: https://github.com/Arno0x/DBC2
        $string1 = /https\:\/\/api\.dropboxapi\.com\// nocase ascii wide

    condition:
        any of them
}
