rule nirsoft_tools
{
    meta:
        description = "Detection patterns for the tool 'nirsoft tools' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "nirsoft tools"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: NirSoft is a legitimate software company that develops system utilities for Windows. Some of its tools can be used by malicious actors to recover passwords harvest sensitive information and conduct password attacks.
        // Reference: N/A
        $string1 = /https\:\/\/www\.nirsoft\.net\/toolsdownload\// nocase ascii wide
        // Description: some of nirsoft tools can be abused by attackers to retrieve passwords 
        // Reference: nirsoft.net
        $string2 = /https\:\/\/www\.nirsoft\.net\/toolsdownload\/.{0,1000}\.exe/ nocase ascii wide
        // Description: some of nirsoft tools can be abused by attackers to retrieve passwords 
        // Reference: nirsoft.net
        $string3 = /https\:\/\/www\.nirsoft\.net\/toolsdownload\/.{0,1000}\.zip/ nocase ascii wide
        // Description: some of nirsoft tools can be abused by attackers to retrieve passwords 
        // Reference: nirsoft.net
        $string4 = /https\:\/\/www\.nirsoft\.net\/utils\/.{0,1000}\.exe/ nocase ascii wide
        // Description: some of nirsoft tools can be abused by attackers to retrieve passwords 
        // Reference: nirsoft.net
        $string5 = /https\:\/\/www\.nirsoft\.net\/utils\/.{0,1000}\.zip/ nocase ascii wide

    condition:
        any of them
}
