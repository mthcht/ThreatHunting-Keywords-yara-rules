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
        $string7 = "0269fd0001afa23edd1206484dccce04b49e0ec0daa65234126a6f3c42f35a46" nocase ascii wide
        // Description: Achieve arbitrary kernel read/writes/function calling in Hypervisor-Protected Code Integrity (HVCI) protected environments calling without admin permissions or kernel drivers - CVE-2024-26229
        // Reference: https://github.com/zer0condition/ZeroHVCI
        $string8 = "95529189-2fb6-49e4-ab2d-3c925ada4414" nocase ascii wide
        // Description: Achieve arbitrary kernel read/writes/function calling in Hypervisor-Protected Code Integrity (HVCI) protected environments calling without admin permissions or kernel drivers - CVE-2024-26229
        // Reference: https://github.com/zer0condition/ZeroHVCI
        $string9 = "c6206e0851a8c6ac7f9a9b6386a7ef7166cfbfc63d04f028cfdbe82ef523acbc" nocase ascii wide
        // Description: Achieve arbitrary kernel read/writes/function calling in Hypervisor-Protected Code Integrity (HVCI) protected environments calling without admin permissions or kernel drivers - CVE-2024-26229
        // Reference: https://github.com/zer0condition/ZeroHVCI
        $string10 = /CSC_DEV_FCB_XXX_CONTROL_FILE.{0,1000}0x001401a3/ nocase ascii wide
        // Description: Achieve arbitrary kernel read/writes/function calling in Hypervisor-Protected Code Integrity (HVCI) protected environments calling without admin permissions or kernel drivers - CVE-2024-26229
        // Reference: https://github.com/zer0condition/ZeroHVCI
        $string11 = "e49b696f9356d17861fb7ff0391a72841af546a18b1be587cf0d41dbdac982a4" nocase ascii wide
        // Description: Achieve arbitrary kernel read/writes/function calling in Hypervisor-Protected Code Integrity (HVCI) protected environments calling without admin permissions or kernel drivers - CVE-2024-26229
        // Reference: https://github.com/zer0condition/ZeroHVCI
        $string12 = /https\:\/\/www\.youtube\.com\/watch\?v\=2eHsnZ4BeDI/ nocase ascii wide
        // Description: Achieve arbitrary kernel read/writes/function calling in Hypervisor-Protected Code Integrity (HVCI) protected environments calling without admin permissions or kernel drivers - CVE-2024-26229
        // Reference: https://github.com/zer0condition/ZeroHVCI
        $string13 = "zer0condition/ZeroHVCI" nocase ascii wide

    condition:
        any of them
}
