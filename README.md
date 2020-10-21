# Sigma
Convert Sigma rules to LogRhythm searches


Conversion from Sigma rules to LogRhythm searches can be done manually by referencing the LogRhythm.yml file to map Sigma fields to LogRhythm filterTypes for use with the LogRhythm Search API. An example of a Sigma rule and the equivalent LogRhythm API search is shown below.

Currently, there is a not an automated LogRhythm conversion for Sigma searches. LogRhythm Search API posts need to be made in JSON format. LogRhythm Search API documentation can be found at https://community.logrhythm.com/ and on your LogRhythm deployment at http://<webconsole>:8505/lr-search-api/docs. 

Sigma searches can also be run in the LogRhythm Web Console or Thick Client. The LogRhythm.yml file also contains comments that map Sigma fields to LogRhythm fields.

Any changes or additions are welcome.

#Example Sigma rule
title: WMI Event Subscription
id: 0f06a3a5-6a09-413f-8743-e6cf35561297
status: experimental
description: Detects creation of WMI event subscription persistence method
tags:
    - attack.t1084          # an old one
    - attack.persistence
    - attack.t1546.003
author: Tom Ueltschi (@c_APT_ure)
date: 2019/01/12
logsource:
    product: windows
    service: sysmon
detection:
    selector:
        EventID:
            - 19
            - 20
            - 21
    condition: selector
falsepositives:
    - exclude legitimate (vetted) use of WMI event subscription in your network
level: high

#Equivalent LogRhythm Search API JSON
{
    "maxMsgsToQuery": 10000,
    "logCacheSize": 10000,
    "queryTimeout": 60,
    "queryRawLog": true,
    "queryEventManager": false,
    "dateCriteria": {
        "useInsertedDate": false,
        "lastIntervalValue": 30,
        "lastIntervalUnit": 4
    },
    "queryLogSources": [],
    "queryFilter": {
        "msgFilterType": 2,
        "isSavedFilter": false,
        "filterGroup": {
            "filterItemType": 1,
            "fieldOperator": 1,
            "filterMode": 1,
            "filterGroupOperator": 0,
            "filterItems": [
                {
                    "filterItemType": 0,
                    "fieldOperator": 0,
                    "filterMode": 1,
                    "filterType": 37,
                    "values": [
                        {
                            "filterType": 37,
                            "valueType": 4,
                            "value": {
                                "value": "19",
                                "matchType": 0
                            },
                        },
                        {
                            "filterType": 37,
                            "valueType": 4,
                            "value": {
                                "value": "20",
                                "matchType": 0
                            },
                        },
                        {
                            "filterType": 37,
                            "valueType": 4,
                            "value": {
                                "value": "21",
                                "matchType": 0
                            },
                        }
                    ],
                }
            ],
        }
    },
}
