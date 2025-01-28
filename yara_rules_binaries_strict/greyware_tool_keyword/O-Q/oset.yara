rule oset
{
    meta:
        description = "Detection patterns for the tool 'oset' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "oset"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string1 = /\sOfflineSamTool\.h/ nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string2 = /\/OfflineSamTool\.exe/ nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string3 = /\/oset\.exe/ nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string4 = /\/oset\.zip/ nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string5 = /\\OfflineSamTool\.exe/ nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string6 = /\\OfflineSamTool\.h/ nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string7 = /\\oset\.exe/ nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string8 = /\\oset\.zip/ nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string9 = /\\Root\\InventoryApplicationFile\\offlinesamtool/ nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string10 = ">Open Source Developer, Grzegorz Tworek<" nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string11 = "03a3b39dd1b9bfb7421e4ba555ca9669b0e3ca7d993ce921d249493aee23b484" nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string12 = "5f87b4ab00f09c64f4d30fcfbf19e9e6945971c74d28370c720e52b83f7decf3" nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string13 = "62440D3B8BE22B9353AC1374CC6ED1FAF4476908FE6D8E9FBD3AA62004EFEF3E" nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string14 = "66092d1e08e55e35b60dc348f2f59d69c0768a09ce411a50fc0d161bfab3303d" nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string15 = "776b64a95ccc334446805d680288c7ac35f1e938ee43115c1911f1c2fed27312" nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string16 = "a5e57662131399ad586e4b5c4a942bc9029104331953fdbdbfd6e8a0cdad9ccc" nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string17 = "b10cfda1-f24f-441b-8f43-80cb93e786ec" nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string18 = "C50B26839FCDA18B4DB6560EB826E94C" nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string19 = "Cannot enumerate SAM objects" nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string20 = "Error converting offlinesam path" nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string21 = "f14052ce01a373effaf1c74eeed9ccda8ac4f6cf3407727d4a5871df9f195f57" nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string22 = "f9ac9d3510fb8c2a50b03605454263af27cf68ef4f27458c03b12607a0f8ebd3" nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string23 = "Offline SAM Editing Tool - Changed" nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string24 = "Offline SAM Editing Tool" nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string25 = "Offline SAM loaded successfully" nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string26 = /Offline\sSAM\sTool\\r\\nUse\swith\scaution\!/ nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string27 = "Open Source Developer, Grzegorz Tworek" nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string28 = /reg\.exe\squery\shklm\s\^\|\sfindstr\s\/i\s\\\\OFFLINE\'/ nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string29 = /reg\.exe\squery\shklm\s\^\|\sfindstr\s\/i\s\\OFFLINE/ nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string30 = "SamOfflineConnect" nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string31 = "SamOfflineEnumerateDomainsInSamServer" nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string32 = "SamOfflineEnumerateUsersInDomain2" nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string33 = "SamOfflineGetMembersInAlias" nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string34 = "SamOfflineLookupDomainInSamServer" nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string35 = "SamOfflineOpenDomain" nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string36 = "SamOfflineOpenUser" nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string37 = "SamOfflineQueryInformationAlias" nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string38 = "SamOfflineQueryInformationUser" nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string39 = "SamOfflineRemoveMemberFromAlias" nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string40 = "SamOfflineRidToSid" nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string41 = "SamOfflineSetInformationAlias" nocase ascii wide
        // Description: Offline SAM Editor Tool to  access and edit SAM databases from offline OS disk
        // Reference: https://x.com/0gtweet/status/1817859483445461406
        $string42 = /stderr\.pl\/oset/ nocase ascii wide
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
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
