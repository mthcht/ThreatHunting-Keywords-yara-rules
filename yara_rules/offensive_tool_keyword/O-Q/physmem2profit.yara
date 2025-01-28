rule physmem2profit
{
    meta:
        description = "Detection patterns for the tool 'physmem2profit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "physmem2profit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string1 = /\sphysmem2minidump\.py/ nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string2 = /\/label\-date\-lsass\.dmp/ nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string3 = /\/physmem2minidump\.py/ nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string4 = /\/physmem2profit\.git/ nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string5 = /\\physmem2minidump\.py/ nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string6 = /\\physmem2profit\-master/ nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string7 = ">physmem2profit<" nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string8 = "23ecca2af6db4c425ab534b9a738f7ec152c7fcf3c250f3ce9d7f57e6259eac9" nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string9 = "814708C9-2320-42D2-A45F-31E42DA06A94" nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string10 = "cc24850f03dccbd8ee3a372b06b2a77a95e5314bb68d2483b1814935978b7003" nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string11 = "MimikatzStream should be at offset " nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string12 = /output.{0,1000}\-lsass\.dmp/ nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string13 = /physmem2profit\.exe/ nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string14 = /Physmem2profit\.sln/ nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string15 = /physmem2profit\-public\.zip/ nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string16 = "source physmem2profit" nocase ascii wide
        // Description: Physmem2profit can be used to create a minidump of a target hosts' LSASS process by analysing physical memory remotely
        // Reference: https://github.com/WithSecureLabs/physmem2profit
        $string17 = "WithSecureLabs/physmem2profit" nocase ascii wide

    condition:
        any of them
}
