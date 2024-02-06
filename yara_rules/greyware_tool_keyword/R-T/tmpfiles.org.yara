rule tmpfiles_org
{
    meta:
        description = "Detection patterns for the tool 'tmpfiles.org' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tmpfiles.org"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: download of an executable files from tmpfiles.org often used by ransomware groups
        // Reference: N/A
        $string1 = /https\:\/\/tmpfiles\.org\/dl\/.{0,1000}\.exe/ nocase ascii wide

    condition:
        any of them
}
