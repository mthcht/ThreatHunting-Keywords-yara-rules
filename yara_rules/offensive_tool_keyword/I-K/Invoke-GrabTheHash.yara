rule Invoke_GrabTheHash
{
    meta:
        description = "Detection patterns for the tool 'Invoke-GrabTheHash' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-GrabTheHash"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Get the NTLM Hash for the User or Machine Account TGT held in your current session
        // Reference: https://github.com/Leo4j/Invoke-GrabTheHash
        $string1 = /\[\-\]\sDomain\sswitch\snot\sprovided\.\sEnumerating\sthe\sDomain\sName/ nocase ascii wide
        // Description: Get the NTLM Hash for the User or Machine Account TGT held in your current session
        // Reference: https://github.com/Leo4j/Invoke-GrabTheHash
        $string2 = /\[\-\]\sStopping\shere\,\sbefore\sgrabbing\sthe\sHash/ nocase ascii wide
        // Description: Get the NTLM Hash for the User or Machine Account TGT held in your current session
        // Reference: https://github.com/Leo4j/Invoke-GrabTheHash
        $string3 = "0592164ed8c8e6330431ba1f8a3eeee650af93d11b4320cfcfda75483b699c32" nocase ascii wide
        // Description: Get the NTLM Hash for the User or Machine Account TGT held in your current session
        // Reference: https://github.com/Leo4j/Invoke-GrabTheHash
        $string4 = "Invoke-GrabTheHash" nocase ascii wide

    condition:
        any of them
}
