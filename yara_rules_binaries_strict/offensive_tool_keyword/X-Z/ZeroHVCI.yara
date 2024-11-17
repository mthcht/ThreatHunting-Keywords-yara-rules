rule ZeroHVCI
{
    meta:
        description = "Detection patterns for the tool 'ZeroHVCI' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ZeroHVCI"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Achieve arbitrary kernel read/writes/function calling in Hypervisor-Protected Code Integrity (HVCI) protected environments calling without admin permissions or kernel drivers - CVE-2024-26229
        // Reference: https://github.com/zer0condition/ZeroHVCI
        $string1 = /\/ZeroHVCI\.exe/ nocase ascii wide
        // Description: Achieve arbitrary kernel read/writes/function calling in Hypervisor-Protected Code Integrity (HVCI) protected environments calling without admin permissions or kernel drivers - CVE-2024-26229
        // Reference: https://github.com/zer0condition/ZeroHVCI
        $string2 = /\/ZeroHVCI\.git/ nocase ascii wide
        // Description: Achieve arbitrary kernel read/writes/function calling in Hypervisor-Protected Code Integrity (HVCI) protected environments calling without admin permissions or kernel drivers - CVE-2024-26229
        // Reference: https://github.com/zer0condition/ZeroHVCI
        $string3 = /\\ZeroHVCI\.cpp/ nocase ascii wide
        // Description: Achieve arbitrary kernel read/writes/function calling in Hypervisor-Protected Code Integrity (HVCI) protected environments calling without admin permissions or kernel drivers - CVE-2024-26229
        // Reference: https://github.com/zer0condition/ZeroHVCI
        $string4 = /\\ZeroHVCI\.exe/ nocase ascii wide
        // Description: Achieve arbitrary kernel read/writes/function calling in Hypervisor-Protected Code Integrity (HVCI) protected environments calling without admin permissions or kernel drivers - CVE-2024-26229
        // Reference: https://github.com/zer0condition/ZeroHVCI
        $string5 = /\\ZeroHVCI\.sln/ nocase ascii wide
        // Description: Achieve arbitrary kernel read/writes/function calling in Hypervisor-Protected Code Integrity (HVCI) protected environments calling without admin permissions or kernel drivers - CVE-2024-26229
        // Reference: https://github.com/zer0condition/ZeroHVCI
        $string6 = /\\ZeroHVCI\-master/ nocase ascii wide
        // Description: Achieve arbitrary kernel read/writes/function calling in Hypervisor-Protected Code Integrity (HVCI) protected environments calling without admin permissions or kernel drivers - CVE-2024-26229
        // Reference: https://github.com/zer0condition/ZeroHVCI
        $string7 = /0269fd0001afa23edd1206484dccce04b49e0ec0daa65234126a6f3c42f35a46/ nocase ascii wide
        // Description: Achieve arbitrary kernel read/writes/function calling in Hypervisor-Protected Code Integrity (HVCI) protected environments calling without admin permissions or kernel drivers - CVE-2024-26229
        // Reference: https://github.com/zer0condition/ZeroHVCI
        $string8 = /95529189\-2fb6\-49e4\-ab2d\-3c925ada4414/ nocase ascii wide
        // Description: Achieve arbitrary kernel read/writes/function calling in Hypervisor-Protected Code Integrity (HVCI) protected environments calling without admin permissions or kernel drivers - CVE-2024-26229
        // Reference: https://github.com/zer0condition/ZeroHVCI
        $string9 = /c6206e0851a8c6ac7f9a9b6386a7ef7166cfbfc63d04f028cfdbe82ef523acbc/ nocase ascii wide
        // Description: Achieve arbitrary kernel read/writes/function calling in Hypervisor-Protected Code Integrity (HVCI) protected environments calling without admin permissions or kernel drivers - CVE-2024-26229
        // Reference: https://github.com/zer0condition/ZeroHVCI
        $string10 = /CSC_DEV_FCB_XXX_CONTROL_FILE.{0,100}0x001401a3/ nocase ascii wide
        // Description: Achieve arbitrary kernel read/writes/function calling in Hypervisor-Protected Code Integrity (HVCI) protected environments calling without admin permissions or kernel drivers - CVE-2024-26229
        // Reference: https://github.com/zer0condition/ZeroHVCI
        $string11 = /e49b696f9356d17861fb7ff0391a72841af546a18b1be587cf0d41dbdac982a4/ nocase ascii wide
        // Description: Achieve arbitrary kernel read/writes/function calling in Hypervisor-Protected Code Integrity (HVCI) protected environments calling without admin permissions or kernel drivers - CVE-2024-26229
        // Reference: https://github.com/zer0condition/ZeroHVCI
        $string12 = /https\:\/\/www\.youtube\.com\/watch\?v\=2eHsnZ4BeDI/ nocase ascii wide
        // Description: Achieve arbitrary kernel read/writes/function calling in Hypervisor-Protected Code Integrity (HVCI) protected environments calling without admin permissions or kernel drivers - CVE-2024-26229
        // Reference: https://github.com/zer0condition/ZeroHVCI
        $string13 = /zer0condition\/ZeroHVCI/ nocase ascii wide
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
