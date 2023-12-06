rule EncryptedZIP
{
    meta:
        description = "Detection patterns for the tool 'EncryptedZIP' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "EncryptedZIP"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Compresses a directory or file and then encrypts the ZIP file with a supplied key using AES256 CFB. This assembly also clears the key out of memory using RtlZeroMemory
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/EncryptedZIP
        $string1 = /\sdecrypt\s.{0,1000}\.aes\.zip/ nocase ascii wide
        // Description: Compresses a directory or file and then encrypts the ZIP file with a supplied key using AES256 CFB. This assembly also clears the key out of memory using RtlZeroMemory
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/EncryptedZIP
        $string2 = /EncryptedZIP\.csproj/ nocase ascii wide
        // Description: Compresses a directory or file and then encrypts the ZIP file with a supplied key using AES256 CFB. This assembly also clears the key out of memory using RtlZeroMemory
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/EncryptedZIP
        $string3 = /EncryptedZIP\.exe/ nocase ascii wide
        // Description: Compresses a directory or file and then encrypts the ZIP file with a supplied key using AES256 CFB. This assembly also clears the key out of memory using RtlZeroMemory
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/EncryptedZIP
        $string4 = /master\/EncryptedZIP/ nocase ascii wide
        // Description: Compresses a directory or file and then encrypts the ZIP file with a supplied key using AES256 CFB. This assembly also clears the key out of memory using RtlZeroMemory
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/EncryptedZIP
        $string5 = /Output\.aes\.zip/ nocase ascii wide

    condition:
        any of them
}
