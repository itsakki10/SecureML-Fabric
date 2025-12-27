def generate_waf_rules(anomaly_score, traffic):
    rules = []

    # Thresholds (simple & explainable)
    if anomaly_score < -0.15:
        rules.append({
            "type": "RATE_LIMIT",
            "description": "High traffic rate detected",
            "rule": "Limit requests to 10 req/sec for this source"
        })

    if traffic["packets"] > 500:
        rules.append({
            "type": "TEMP_BLOCK",
            "description": "Excessive packet count",
            "rule": "Block source IP for 10 minutes"
        })

    if traffic["bytes"] > 200000:
        rules.append({
            "type": "MODSEC_RULE",
            "description": "Abnormal data transfer size",
            "rule": (
                "SecRule REQUEST_HEADERS:Content-Length "
                "\"@gt 200000\" "
                "\"id:1001,phase:1,deny,status:403,msg:'Abnormal payload size'\""
            )
        })

    return rules
