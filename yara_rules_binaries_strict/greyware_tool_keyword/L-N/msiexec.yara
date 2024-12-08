rule msiexec
{
    meta:
        description = "Detection patterns for the tool 'msiexec' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "msiexec"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string1 = /MsiExec\.exe\s\/qn\s\/X\{01423865\-551B\-4C59\-B44A\-CC604BC21AF3\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string2 = /MsiExec\.exe\s\/qn\s\/X\{1093B57D\-A613\-47F3\-90CF\-0FD5C5DCFFE6\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string3 = /MsiExec\.exe\s\/qn\s\/X\{1FFD3F20\-5D24\-4C9A\-B9F6\-A207A53CF179\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string4 = /MsiExec\.exe\s\/qn\s\/X\{2519A41E\-5D7C\-429B\-B2DB\-1E943927CB3D\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string5 = /MsiExec\.exe\s\/qn\s\/X\{2831282D\-8519\-4910\-B339\-2302840ABEF3\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string6 = /MsiExec\.exe\s\/qn\s\/X\{2C14E1A2\-C4EB\-466E\-8374\-81286D723D3A\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string7 = /MsiExec\.exe\s\/qn\s\/X\{36333618\-1CE1\-4EF2\-8FFD\-7F17394891CE\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string8 = /MsiExec\.exe\s\/qn\s\/X\{3B998572\-90A5\-4D61\-9022\-00B288DD755D\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string9 = /MsiExec\.exe\s\/qn\s\/X\{425063CE\-9566\-43B8\-AC61\-F8D182828634\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string10 = /MsiExec\.exe\s\/qn\s\/X\{4627F5A1\-E85A\-4394\-9DB3\-875DF83AF6C2\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string11 = /MsiExec\.exe\s\/qn\s\/X\{4BAF6F55\-FFE4\-4A3A\-8367\-CC2EBB0F11C3\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string12 = /MsiExec\.exe\s\/qn\s\/X\{4EFCDD15\-24A2\-4D89\-84A4\-857D1BF68FA8\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string13 = /MsiExec\.exe\s\/qn\s\/X\{604350BF\-BE9A\-4F79\-B0EB\-B1C22D889E2D\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string14 = /MsiExec\.exe\s\/qn\s\/X\{6654537D\-935E\-41C0\-A18A\-C55C2BF77B7E\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string15 = /MsiExec\.exe\s\/qn\s\/X\{66967E5F\-43E8\-4402\-87A4\-04685EE5C2CB\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string16 = /MsiExec\.exe\s\/qn\s\/X\{72E136F7\-3751\-422E\-AC7A\-1B2E46391909\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string17 = /MsiExec\.exe\s\/qn\s\/X\{72E30858\-FC95\-4C87\-A697\-670081EBF065\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string18 = /MsiExec\.exe\s\/qn\s\/X\{77F92E90\-ED4F\-4CFF\-8F60\-3E3E4AEB705C\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string19 = /MsiExec\.exe\s\/qn\s\/X\{7CD26A0C\-9B59\-4E84\-B5EE\-B386B2F7AA16\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string20 = /MsiExec\.exe\s\/qn\s\/X\{80D18B7B\-8DF1\-4BCA\-901F\-BEC86BAE2774\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string21 = /MsiExec\.exe\s\/qn\s\/X\{8123193C\-9000\-4EEB\-B28A\-E74E779759FA\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string22 = /MsiExec\.exe\s\/qn\s\/X\{85F78DA7\-8E8E\-49C9\-969F\-A62D2B43C046\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string23 = /MsiExec\.exe\s\/qn\s\/X\{934BEF80\-B9D1\-4A86\-8B42\-D8A6716A8D27\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string24 = /MsiExec\.exe\s\/qn\s\/X\{9D1B8594\-5DD2\-4CDC\-A5BD\-98E7E9D75520\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string25 = /MsiExec\.exe\s\/qn\s\/X\{A1DC5EF8\-DD20\-45E8\-ABBD\-F529A24D477B\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string26 = /MsiExec\.exe\s\/qn\s\/X\{A5CCEEF1\-B6A7\-4EB4\-A826\-267996A62A9E\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string27 = /MsiExec\.exe\s\/qn\s\/X\{AFBCA1B9\-496C\-4AE6\-98AE\-3EA1CFF65C54\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string28 = /MsiExec\.exe\s\/qn\s\/X\{B9C2F07D\-1137\-4E3D\-B22B\-05144293EF42\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string29 = /MsiExec\.exe\s\/qn\s\/X\{BA8752FE\-75E5\-43DD\-9913\-23509EFEB409\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string30 = /MsiExec\.exe\s\/qn\s\/X\{BB36D9C2\-6AE5\-4AB2\-BC91\-ECD247092BD8\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string31 = /MsiExec\.exe\s\/qn\s\/X\{BCF53039\-A7FC\-4C79\-A3E3\-437AE28FD918\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string32 = /MsiExec\.exe\s\/qn\s\/X\{CA3CE456\-B2D9\-4812\-8C69\-17D6980432EF\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string33 = /MsiExec\.exe\s\/qn\s\/X\{CA524364\-D9C5\-4804\-92DE\-2800BDAC1AA4\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string34 = /MsiExec\.exe\s\/qn\s\/X\{D29542AE\-287C\-42E4\-AB28\-3858E13C1A3E\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string35 = /MsiExec\.exe\s\/qn\s\/X\{D5BC54B8\-1DA1\-44F4\-AE6F\-86E05CDB0B44\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string36 = /MsiExec\.exe\s\/qn\s\/X\{D875F30C\-B469\-4998\-9A08\-FE145DD5DC1A\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string37 = /MsiExec\.exe\s\/qn\s\/X\{DFDA2077\-95D0\-4C5F\-ACE7\-41DA16639255\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string38 = /MsiExec\.exe\s\/qn\s\/X\{DFFA9361\-3625\-4219\-82C2\-9EF011E433B1\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string39 = /MsiExec\.exe\s\/qn\s\/X\{E44AF5E6\-7D11\-4BDF\-BEA8\-AA7AE5FE6745\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string40 = /MsiExec\.exe\s\/qn\s\/X\{E82DD0A8\-0E5C\-4D72\-8DDE\-41BB0FC06B3E\}\sREBOOT\=ReallySuppress/ nocase ascii wide
        // Description: Uninstall Sophos products
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string41 = /MsiExec\.exe\s\/X\{1AC3C833\-D493\-460C\-816F\-D26F30F79DC3\}\s\/qn/ nocase ascii wide
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
