rule phoenix_miner
{
    meta:
        description = "Detection patterns for the tool 'phoenix miner' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "phoenix miner"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Phoenix Miner is a popular. efficient. fast. and cost-effective Ethereum miner with support for both AMD and Nvidia GPUs. It's intended to be used for legitimate cryptocurrency mining purposes.Attackers can secretly install Phoenix Miner on unsuspecting users' computers to mine cryptocurrency for themselves. This is often done by bundling the miner with other software or hiding it within malicious attachments or downloads. The computer then slow down due to the high CPU and GPU usage
        // Reference: N/A
        $string1 = /PhoenixMiner\.exe/ nocase ascii wide
        // Description: Phoenix Miner is a popular. efficient. fast. and cost-effective Ethereum miner with support for both AMD and Nvidia GPUs. It's intended to be used for legitimate cryptocurrency mining purposes.Attackers can secretly install Phoenix Miner on unsuspecting users' computers to mine cryptocurrency for themselves. This is often done by bundling the miner with other software or hiding it within malicious attachments or downloads. The computer then slow down due to the high CPU and GPU usage
        // Reference: N/A
        $string2 = /PhoenixMiner_.{0,1000}_Windows\\/ nocase ascii wide

    condition:
        any of them
}
