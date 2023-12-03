rule Payload_Download_Cradles
{
    meta:
        description = "Detection patterns for the tool 'Payload-Download-Cradles' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Payload-Download-Cradles"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This are different types of download cradles which should be an inspiration to play and create new download cradles to bypass AV/EPP/EDR in context of download cradle detections.
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string1 = /.{0,1000}Download:Cradle\.js.{0,1000}/ nocase ascii wide
        // Description: This are different types of download cradles which should be an inspiration to play and create new download cradles to bypass AV/EPP/EDR in context of download cradle detections.
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string2 = /.{0,1000}Download_Cradles\..{0,1000}/ nocase ascii wide
        // Description: This are different types of download cradles which should be an inspiration to play and create new download cradles to bypass AV/EPP/EDR in context of download cradle detections.
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string3 = /.{0,1000}Download\-Cradles\.cmd.{0,1000}/ nocase ascii wide
        // Description: This are different types of download cradles which should be an inspiration to play and create new download cradles to bypass AV/EPP/EDR in context of download cradle detections.
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string4 = /.{0,1000}Payload\-Download\-Cradles.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
