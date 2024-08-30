rule Greenwolf
{
    meta:
        description = "Detection patterns for the tool 'Greenwolf' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Greenwolf"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Social Media Mapping Tool that correlates profiles via facial recognition by Jacob Wilkin (Greenwolf).Social Mapper is an Open Source Intelligence Tool that uses facial recognition to correlate social media profiles across different sites on a large scale. It takes an automated approach to search popular social media sites for targets' names and pictures to accurately detect and group a persons presence. outputting the results into report that a human operator can quickly review.Social Mapper has a variety of uses in the security industry. for example the automated gathering of large amounts of social media profiles for use on targeted phishing campaigns. Facial recognition aids this process by removing false positives in the search results. so that reviewing this data is quicker for a human operator.
        // Reference: https://github.com/Greenwolf/social_mapper
        $string1 = /Greenwolf/ nocase ascii wide

    condition:
        any of them
}
