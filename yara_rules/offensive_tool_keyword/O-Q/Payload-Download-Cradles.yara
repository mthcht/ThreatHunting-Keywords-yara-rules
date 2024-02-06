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
        $string1 = /Download\:Cradle\.js/ nocase ascii wide
        // Description: This are different types of download cradles which should be an inspiration to play and create new download cradles to bypass AV/EPP/EDR in context of download cradle detections.
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string2 = /Download_Cradles\./ nocase ascii wide
        // Description: This are different types of download cradles which should be an inspiration to play and create new download cradles to bypass AV/EPP/EDR in context of download cradle detections.
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string3 = /Download\-Cradles\.cmd/ nocase ascii wide
        // Description: This are different types of download cradles which should be an inspiration to play and create new download cradles to bypass AV/EPP/EDR in context of download cradle detections.
        // Reference: https://github.com/VirtualAlllocEx/Payload-Download-Cradles
        $string4 = /Payload\-Download\-Cradles/ nocase ascii wide

    condition:
        any of them
}
