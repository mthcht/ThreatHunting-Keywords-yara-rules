rule Compress_Archive
{
    meta:
        description = "Detection patterns for the tool 'Compress-Archive' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Compress-Archive"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Compress data using zlib for exfiltration
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string1 = /\:\\programdata\\cloud\.exe/ nocase ascii wide
        // Description: Compress data using zlib for exfiltration
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string2 = /Compress\-Archive\s\-Path.{0,1000}\-DestinationPath\s\$env\:TEMP/ nocase ascii wide
        // Description: Compress data using zlib for exfiltration
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string3 = /Compress\-Archive\s\-Path.{0,1000}\-DestinationPath.{0,1000}\:\\Windows\\Temp\\/ nocase ascii wide
        // Description: Compress data using zlib for exfiltration
        // Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a
        $string4 = /Compress\-Archive\s\-Path.{0,1000}\-DestinationPath.{0,1000}\\AppData\\Local\\Temp\\\'/ nocase ascii wide

    condition:
        any of them
}
