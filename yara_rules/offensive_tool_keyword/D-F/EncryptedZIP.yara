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
        $string1 = /.{0,1000}\sdecrypt\s.{0,1000}\.aes\.zip.{0,1000}/ nocase ascii wide
        // Description: Compresses a directory or file and then encrypts the ZIP file with a supplied key using AES256 CFB. This assembly also clears the key out of memory using RtlZeroMemory
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/EncryptedZIP
        $string2 = /.{0,1000}EncryptedZIP\.csproj.{0,1000}/ nocase ascii wide
        // Description: Compresses a directory or file and then encrypts the ZIP file with a supplied key using AES256 CFB. This assembly also clears the key out of memory using RtlZeroMemory
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/EncryptedZIP
        $string3 = /.{0,1000}EncryptedZIP\.exe.{0,1000}/ nocase ascii wide
        // Description: Compresses a directory or file and then encrypts the ZIP file with a supplied key using AES256 CFB. This assembly also clears the key out of memory using RtlZeroMemory
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/EncryptedZIP
        $string4 = /.{0,1000}master\/EncryptedZIP.{0,1000}/ nocase ascii wide
        // Description: Compresses a directory or file and then encrypts the ZIP file with a supplied key using AES256 CFB. This assembly also clears the key out of memory using RtlZeroMemory
        // Reference: https://github.com/matterpreter/OffensiveCSharp/tree/master/EncryptedZIP
        $string5 = /.{0,1000}Output\.aes\.zip.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
