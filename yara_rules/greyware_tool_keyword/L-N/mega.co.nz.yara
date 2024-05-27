rule mega_co_nz
{
    meta:
        description = "Detection patterns for the tool 'mega.co.nz' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mega.co.nz"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: uploading data to mega cloud
        // Reference: https://mega.io/
        $string1 = /\.userstorage\.mega\.co\.nz\/ul\// nocase ascii wide

    condition:
        any of them
}
