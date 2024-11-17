rule Azure_Storage_Explorer
{
    meta:
        description = "Detection patterns for the tool 'Azure Storage Explorer' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Azure Storage Explorer"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: legitimate microsoft software - threat actors have been abusing Azure Storage Explorer for Data Exfiltration
        // Reference: https://azure.microsoft.com/en-us/products/storage/storage-explorer
        $string1 = /\/Microsoft\sAzure\sStorage\sExplorer\.app/ nocase ascii wide
        // Description: legitimate microsoft software - threat actors have been abusing Azure Storage Explorer for Data Exfiltration
        // Reference: https://azure.microsoft.com/en-us/products/storage/storage-explorer
        $string2 = /\/Microsoft\sAzure\sStorage\sExplorer\.zip/ nocase ascii wide
        // Description: legitimate microsoft software - threat actors have been abusing Azure Storage Explorer for Data Exfiltration
        // Reference: https://azure.microsoft.com/en-us/products/storage/storage-explorer
        $string3 = /\\Microsoft\sAzure\sStorage\sExplorer\.zip/ nocase ascii wide
        // Description: legitimate microsoft software - threat actors have been abusing Azure Storage Explorer for Data Exfiltration
        // Reference: https://azure.microsoft.com/en-us/products/storage/storage-explorer
        $string4 = /\>Microsoft\sAzure\sStorage\sExplorer\sSetup\</ nocase ascii wide
        // Description: legitimate microsoft software - threat actors have been abusing Azure Storage Explorer for Data Exfiltration
        // Reference: https://azure.microsoft.com/en-us/products/storage/storage-explorer
        $string5 = /\>Microsoft\sAzure\sStorage\sExplorer\</ nocase ascii wide
        // Description: legitimate microsoft software - threat actors have been abusing Azure Storage Explorer for Data Exfiltration
        // Reference: https://azure.microsoft.com/en-us/products/storage/storage-explorer
        $string6 = /036a9029e3b883ded8de9d9bdde3f63dd86d3403b7ed767b1efc3037c9d37bc4/ nocase ascii wide
        // Description: legitimate microsoft software - threat actors have been abusing Azure Storage Explorer for Data Exfiltration
        // Reference: https://azure.microsoft.com/en-us/products/storage/storage-explorer
        $string7 = /7fa49a08d05a3616b5a24f52645d76c4496c37f5060a6bd4a648f534c4e85ae0/ nocase ascii wide
        // Description: legitimate microsoft software - threat actors have been abusing Azure Storage Explorer for Data Exfiltration
        // Reference: https://azure.microsoft.com/en-us/products/storage/storage-explorer
        $string8 = /c798b2aedc7a74f0daf51eb216aae8cb48b45f208b0409916442b1d61d2ad2ef/ nocase ascii wide
        // Description: legitimate microsoft software - threat actors have been abusing Azure Storage Explorer for Data Exfiltration
        // Reference: https://azure.microsoft.com/en-us/products/storage/storage-explorer
        $string9 = /com\.microsoft\.StorageExplorer/ nocase ascii wide
        // Description: legitimate microsoft software - threat actors have been abusing Azure Storage Explorer for Data Exfiltration
        // Reference: https://azure.microsoft.com/en-us/products/storage/storage-explorer
        $string10 = /Microsoft\sAzure\sStorage\sExplorer\.app\/Contents\// nocase ascii wide
        // Description: legitimate microsoft software - threat actors have been abusing Azure Storage Explorer for Data Exfiltration
        // Reference: https://azure.microsoft.com/en-us/products/storage/storage-explorer
        $string11 = /StorageExplorer\-linux\-x64\.tar\.gz/ nocase ascii wide
        // Description: legitimate microsoft software - threat actors have been abusing Azure Storage Explorer for Data Exfiltration
        // Reference: https://azure.microsoft.com/en-us/products/storage/storage-explorer
        $string12 = /StorageExplorer\-windows\-x64\.exe/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and any of ($string*)) or
        (filesize < 2MB and
        (
            any of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
