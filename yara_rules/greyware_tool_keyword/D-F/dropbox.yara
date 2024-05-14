rule dropbox
{
    meta:
        description = "Detection patterns for the tool 'dropbox' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "dropbox"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: uploading file to dropbox with the API
        // Reference: https://github.com/I-Am-Jakoby/PowerShell-for-Hackers/blob/main/Functions/DropBox-Upload.md
        $string1 = /https\:\/\/content\.dropboxapi\.com\/2\/files\/upload/ nocase ascii wide

    condition:
        any of them
}
