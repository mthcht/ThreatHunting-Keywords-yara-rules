rule FOCA
{
    meta:
        description = "Detection patterns for the tool 'FOCA' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FOCA"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: FOCA is a tool used mainly to find metadata and hidden information in the documents it scans. These documents may be on web pages. and can be downloaded and analysed with FOCA.It is capable of analysing a wide variety of documents. with the most common being Microsoft Office. Open Office. or PDF files. although it also analyses Adobe InDesign or SVG files. for instance.
        // Reference: https://github.com/ElevenPaths/FOCA
        $string1 = /ElevenPaths.{0,1000}FOCA/ nocase ascii wide

    condition:
        any of them
}
