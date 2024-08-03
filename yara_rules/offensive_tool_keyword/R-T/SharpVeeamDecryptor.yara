rule SharpVeeamDecryptor
{
    meta:
        description = "Detection patterns for the tool 'SharpVeeamDecryptor' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpVeeamDecryptor"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Decrypt Veeam database passwords
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpVeeamDecryptor
        $string1 = /\"VeeamBackupCreds\"/ nocase ascii wide
        // Description: Decrypt Veeam database passwords
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpVeeamDecryptor
        $string2 = /\/SharpVeeamDecryptor\./ nocase ascii wide
        // Description: Decrypt Veeam database passwords
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpVeeamDecryptor
        $string3 = /\\SharpVeeamDecryptor\-/ nocase ascii wide
        // Description: Decrypt Veeam database passwords
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpVeeamDecryptor
        $string4 = /\\SharpVeeamDecryptor\./ nocase ascii wide
        // Description: Decrypt Veeam database passwords
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpVeeamDecryptor
        $string5 = /\>VeeamBackupCreds\</ nocase ascii wide
        // Description: Decrypt Veeam database passwords
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpVeeamDecryptor
        $string6 = /267c2cc1712018393f79e00ee869f86e8be7522569e18ec76ab2c8deb36ba9d1/ nocase ascii wide
        // Description: Decrypt Veeam database passwords
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpVeeamDecryptor
        $string7 = /a0b465738c8244eae2e5b1c2574e621b044405cf9c3a574e44737ff08f9ea442/ nocase ascii wide
        // Description: Decrypt Veeam database passwords
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpVeeamDecryptor
        $string8 = /Author\:\s\@ShitSecure/ nocase ascii wide
        // Description: Decrypt Veeam database passwords
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpVeeamDecryptor
        $string9 = /d5fb8f91ffff93aecf6c68f864ce853a541d0bb7b53db3f5eb2fd6b8310cc5f2/ nocase ascii wide
        // Description: Decrypt Veeam database passwords
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpVeeamDecryptor
        $string10 = /EE728741\-4BD4\-4F7C\-8E41\-B8328706EA84/ nocase ascii wide
        // Description: Decrypt Veeam database passwords
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpVeeamDecryptor
        $string11 = /f2514c44ea0566d15601e6179fab45dbb023b78cb0903a28196a31599f17be00/ nocase ascii wide
        // Description: Decrypt Veeam database passwords
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpVeeamDecryptor
        $string12 = /GetRegistryValue.{0,1000}SOFTWARE\\Veeam\\Veeam\sBackup\sCatalog/ nocase ascii wide
        // Description: Decrypt Veeam database passwords
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpVeeamDecryptor
        $string13 = /S3cur3Th1sSh1t\/SharpVeeamDecryptor/ nocase ascii wide
        // Description: Decrypt Veeam database passwords
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpVeeamDecryptor
        $string14 = /SELECT\suser_name\,\spassword\sFROM\sVeeamBackup\.dbo\.Credentials/ nocase ascii wide
        // Description: Decrypt Veeam database passwords
        // Reference: https://github.com/S3cur3Th1sSh1t/SharpVeeamDecryptor
        $string15 = /SharpVeeamDecryptor\.exe/ nocase ascii wide

    condition:
        any of them
}
