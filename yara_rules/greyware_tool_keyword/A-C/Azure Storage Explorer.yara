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

    condition:
        any of them
}
