rule mediafire
{
    meta:
        description = "Detection patterns for the tool 'mediafire' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mediafire"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: downloading from mediafire
        // Reference: N/A
        $string1 = /\/download.{0,1000}mediafire\.com\// nocase ascii wide
        // Description: downloading from mediafire
        // Reference: N/A
        $string2 = /https\:\/\/www\.mediafire\.com\/api\/.{0,1000}\/folder\/get_content\.php/ nocase ascii wide
        // Description: uploading to mediafire
        // Reference: N/A
        $string3 = /www\.mediafire\.com\/api\/1\.5\/upload\// nocase ascii wide
        // Description: downloading from mediafire
        // Reference: N/A
        $string4 = /www\.mediafire\.com\/file\// nocase ascii wide
        // Description: downloading from mediafire - rar archive
        // Reference: N/A
        $string5 = /www\.mediafire\.com\/file\/.{0,1000}\.rar\/file/ nocase ascii wide
        // Description: uploading to mediafire
        // Reference: N/A
        $string6 = /www\.mediafireuserupload\.com\/api\/upload\// nocase ascii wide

    condition:
        any of them
}
