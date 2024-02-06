rule index_allocation
{
    meta:
        description = "Detection patterns for the tool '$index_allocation' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "$index_allocation"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: creation of hidden folders (and file) via ...$.......::$index_allocation
        // Reference: https://soroush.me/blog/2010/12/a-dotty-salty-directory-a-secret-place-in-ntfs-for-secret-files/
        $string1 = /\.\.\.\:\:\$index_allocation/ nocase ascii wide
        // Description: creation of hidden folders (and file) via ...$.......::$index_allocation
        // Reference: https://soroush.me/blog/2010/12/a-dotty-salty-directory-a-secret-place-in-ntfs-for-secret-files/
        $string2 = /cd\s.{0,1000}\.\:\:\$index_allocation/ nocase ascii wide
        // Description: creation of hidden folders (and file) via ...$.......::$index_allocation
        // Reference: https://soroush.me/blog/2010/12/a-dotty-salty-directory-a-secret-place-in-ntfs-for-secret-files/
        $string3 = /md\s.{0,1000}\.\:\:\$index_allocation/ nocase ascii wide

    condition:
        any of them
}
