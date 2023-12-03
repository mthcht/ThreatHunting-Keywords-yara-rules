rule smbcrawler
{
    meta:
        description = "Detection patterns for the tool 'smbcrawler' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "smbcrawler"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: SmbCrawler is a tool that takes credentials and a list of hosts and crawls through those shares
        // Reference: https://github.com/SySS-Research/smbcrawler
        $string1 = /.{0,1000}impacket\.smbconnection.{0,1000}/ nocase ascii wide
        // Description: SmbCrawler is a tool that takes credentials and a list of hosts and crawls through those shares
        // Reference: https://github.com/SySS-Research/smbcrawler
        $string2 = /.{0,1000}smbcrawler.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
