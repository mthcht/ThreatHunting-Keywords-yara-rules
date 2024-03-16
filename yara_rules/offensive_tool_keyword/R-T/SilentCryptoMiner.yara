rule SilentCryptoMiner
{
    meta:
        description = "Detection patterns for the tool 'SilentCryptoMiner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SilentCryptoMiner"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Silent (Hidden) Free Crypto Miner Builder
        // Reference: https://github.com/UnamSanctam/SilentCryptoMiner
        $string1 = /\/SilentCryptoMiner\// nocase ascii wide
        // Description: A Silent (Hidden) Free Crypto Miner Builder
        // Reference: https://github.com/UnamSanctam/SilentCryptoMiner
        $string2 = /\@etc\.2miners\.com\:/ nocase ascii wide
        // Description: A Silent (Hidden) Free Crypto Miner Builder
        // Reference: https://github.com/UnamSanctam/SilentCryptoMiner
        $string3 = /\\ethminer\.exe/ nocase ascii wide
        // Description: A Silent (Hidden) Free Crypto Miner Builder
        // Reference: https://github.com/UnamSanctam/SilentCryptoMiner
        $string4 = /\\MinerETH\.cs/ nocase ascii wide
        // Description: A Silent (Hidden) Free Crypto Miner Builder
        // Reference: https://github.com/UnamSanctam/SilentCryptoMiner
        $string5 = /\\MinerXMR\.cs/ nocase ascii wide
        // Description: A Silent (Hidden) Free Crypto Miner Builder
        // Reference: https://github.com/UnamSanctam/SilentCryptoMiner
        $string6 = /\\SilentCryptoMiner\\/ nocase ascii wide
        // Description: A Silent (Hidden) Free Crypto Miner Builder
        // Reference: https://github.com/UnamSanctam/SilentCryptoMiner
        $string7 = /\\SysWhispersU\.exe/ nocase ascii wide
        // Description: A Silent (Hidden) Free Crypto Miner Builder
        // Reference: https://github.com/UnamSanctam/SilentCryptoMiner
        $string8 = /\\xmrig\.exe/ nocase ascii wide
        // Description: A Silent (Hidden) Free Crypto Miner Builder
        // Reference: https://github.com/UnamSanctam/SilentCryptoMiner
        $string9 = /8BbApiMBHsPVKkLEP4rVbST6CnSb3LW2gXygngCi5MGiBuwAFh6bFEzT3UTufiCehFK7fNvAjs5Tv6BKYa6w8hwaSjnsg2N\./ nocase ascii wide
        // Description: A Silent (Hidden) Free Crypto Miner Builder
        // Reference: https://github.com/UnamSanctam/SilentCryptoMiner
        $string10 = /A\sSilent\s\(Hidden\)\sFree\sCrypto\sMiner\sBuilder/ nocase ascii wide
        // Description: A Silent (Hidden) Free Crypto Miner Builder
        // Reference: https://github.com/UnamSanctam/SilentCryptoMiner
        $string11 = /CE2307EB\-A69E\-0EB9\-386C\-D322223A10A9/ nocase ascii wide
        // Description: A Silent (Hidden) Free Crypto Miner Builder
        // Reference: https://github.com/UnamSanctam/SilentCryptoMiner
        $string12 = /Company\'\>Unam\sSanctam\<\/Data\>/ nocase ascii wide
        // Description: A Silent (Hidden) Free Crypto Miner Builder
        // Reference: https://github.com/UnamSanctam/SilentCryptoMiner
        $string13 = /namespace\sSilentCryptoMiner/ nocase ascii wide
        // Description: A Silent (Hidden) Free Crypto Miner Builder
        // Reference: https://github.com/UnamSanctam/SilentCryptoMiner
        $string14 = /Silent\sCrypto\sMiner\sBuilder/ nocase ascii wide
        // Description: A Silent (Hidden) Free Crypto Miner Builder
        // Reference: https://github.com/UnamSanctam/SilentCryptoMiner
        $string15 = /Silent\.Crypto\.Miner\.Builder\.zip/ nocase ascii wide
        // Description: A Silent (Hidden) Free Crypto Miner Builder
        // Reference: https://github.com/UnamSanctam/SilentCryptoMiner
        $string16 = /SilentCryptoMiner\.sln/ nocase ascii wide
        // Description: A Silent (Hidden) Free Crypto Miner Builder
        // Reference: https://github.com/UnamSanctam/SilentCryptoMiner
        $string17 = /SilentCryptoMiner\-scm\-v/ nocase ascii wide
        // Description: A Silent (Hidden) Free Crypto Miner Builder
        // Reference: https://github.com/UnamSanctam/SilentCryptoMiner
        $string18 = /xmr\.2miners\.com/ nocase ascii wide

    condition:
        any of them
}
