rule pth_toolkit
{
    meta:
        description = "Detection patterns for the tool 'pth-toolkit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pth-toolkit"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string1 = /\/pth\-toolkit\.git/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string2 = /\\pth\-toolkit\-master\\/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string3 = /127f1bfca312fa054a6e761df8c330967ed93dbe80ca78357e9b727faea0c5ef/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string4 = /21f59168d9679a4567facac1b9146c930bc5e47c7c5ad248ed9e4e4582c25008/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string5 = /26048dbf252141d3db4df311c6d70188c91bf1e4d3bb8cd8870b373566562a1d/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string6 = /2e70b4bcc21c4aba64c283af815b20d52c79c93f14f9df623a6e588491155acf/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string7 = /5ba6551843aaa623f0acd46941837e7dfde53ebbb648187a7f92efd211909d4f/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string8 = /645524305b8203fddf667329025f7ce531c9bc664f3186d5db5cfa0ff55d53b5/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string9 = /7bb549f48f1f33ad7f2494b078459ddd2a70c39ccc34a6edf3c0b9cd5efc9031/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string10 = /9d3ebfe38c45da2bedc4250b4a5b8dcfe4a6c3505ccfe9a429f39b06a8ecc228/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string11 = /b54792e5bf55da77fb025772858aee457ee4f679a8363faf35d0397db897b92a/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string12 = /bb816067581c9cd64ea54ff05611c02efa4303ef95c86e027ca26aa2ae80c185/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string13 = /bca5760a0654e457801cbc90c173703da7b359376a5c8855d1e7bd451a0e421b/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string14 = /bf5a2aafdd2a8719cc733808bdb7009e6a7d4e6b889faa8a52e95b5ecc5d2337/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string15 = /byt3bl33d3r\/pth\-toolkit/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string16 = /db7c868e3042fbf2138bf10e7dae3fb72f38a269a6337e87669829a416aa3109/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string17 = /e696484e41d70abaa95a09f2c77e5198a6556f5f5884f0d84bf21c5926c5afc7/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string18 = /pth\-rpcclient/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string19 = /pth\-smbclient/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string20 = /pth\-smbget/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string21 = /pth\-toolkit/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string22 = /pth\-toolkit\-master\.zip/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string23 = /pth\-winexe/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string24 = /pth\-wmic/ nocase ascii wide
        // Description: A modified version of the passing-the-hash tool collection https://code.google.com/p/passing-the-hash/ designed to be portable and work straight out of the box even on the most 'bare bones' systems
        // Reference: https://github.com/byt3bl33d3r/pth-toolkit
        $string25 = /pth\-wmis/ nocase ascii wide

    condition:
        any of them
}
