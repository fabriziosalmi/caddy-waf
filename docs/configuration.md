# ⚙️ Configuration

Understanding how the Caddy Web Application Firewall (WAF) processes incoming requests, evaluates rules, and decides when to block a request is crucial for effective configuration and management. This section explains the request lifecycle within the WAF, including the order of operations and the logic behind blocking decisions.

---

## **Request Processing Flow: From Caddy to the WAF**

1. **Incoming Request:**  
   When a client sends an HTTP request to your Caddy server, it is first handled by Caddy's core request-handling mechanism.

2. **WAF Middleware Invoked:**  
   If a `waf` block is configured in your `Caddyfile`, the WAF middleware is invoked as the first handler in the route.

3. **Request Context Initialization:**  
   The WAF initializes a `WAFState` struct for each incoming request. This struct holds:
   - The request's anomaly score (`TotalScore`).
   - Its blocking status (`Blocked`).
   - The response status code (`StatusCode`).
   - A unique log identifier for tracing the request in logs.

4. **Phase-Based Evaluation:**  
   The WAF processes the request in distinct phases, each representing a specific stage of the request lifecycle. Phases are executed in numerical order:

   - **Phase 1: Request Headers (and Early Checks)**  
     This phase occurs before the request body is parsed and includes:
     - **Country Blocking/Whitelisting (Optional):**  
       Checks the request's source IP against a configured country list. If the IP originates from a blocked country (or not from a whitelisted country), the request is immediately blocked.
     - **Rate Limiting (Optional):**  
       Checks the rate limiter against the client IP and request path. If the request count exceeds the limit within the configured time window, the request is blocked.
     - **IP Blacklisting:**  
       Checks the request's source IP against the configured IP blacklist. If a match is found (direct IP or CIDR range), the request is blocked.
     - **DNS Blacklisting:**  
       Checks the request's `Host` header against the DNS blacklist. If a match is found, the request is blocked.
     - **Rule Evaluation for Request Headers:**  
       Checks the request headers against the configured rules for Phase 1.

   - **Phase 2: Request Body:**  
     Analyzes the request body against rules configured for this phase, looking for malicious payloads.

   - **Phase 3: Response Headers:**  
     After the request is processed by the backend, the WAF analyzes the response headers before sending them to the client, looking for malicious payloads or unintended information.

   - **Phase 4: Response Body:**  
     After the response is processed by the backend, the WAF analyzes the response body before sending it to the client, looking for malicious or unintended content.

5. **Rule Evaluation within Each Phase:**  
   - For each phase, the WAF iterates through the rules defined for that phase, respecting their order and priority.
   - For each rule, the WAF extracts the configured `target` (e.g., URL, headers, body, cookies) from the request (or response in Phases 3 and 4).
   - The extracted value is matched against the rule's regular expression (`pattern`).
   - If a match is found:
     - The rule's hit count is incremented.
     - The rule's score is added to the request's `TotalScore`.
     - The WAF checks if the rule's action is `block` or if the `TotalScore` exceeds the `anomaly_threshold`.
     - If either condition is met:
       - The request is marked as `Blocked`.
       - The response status code is set to `403 Forbidden` (customizable).
       - A `WARN` log entry is created with details about the blocked request.
       - If a custom response is defined, it is sent to the client.
       - Request processing stops immediately, and no further WAF rules or handlers are executed.
     - If the rule's action is `log`, the match is logged at `INFO` level, and the request continues processing.

6. **Request Continues or Blocked:**  
   - If the request is not `Blocked`, it proceeds to the next handler on the route (e.g., your application's handler).
   - If the request is `Blocked`, a `403` error (or custom response) is returned to the client, and no further handlers are executed.

7. **Metrics Collection:**  
   For every request processed, the WAF updates internal counters:
   - `total_requests`: Incremented for all requests.
   - `blocked_requests`: Incremented if the request is blocked.
   - `allowed_requests`: Incremented if the request is allowed.

8. **Metrics Exposure:**  
   A `/waf_metrics` endpoint provides a JSON output of these metrics for monitoring and troubleshooting, offering insights into WAF activity.

---

## **Blocking Logic and Precedence**

- **Early Checks Take Precedence:**  
  Country blocking/whitelisting, rate limiting, IP blacklisting, and DNS blacklisting in Phase 1 take precedence over rule-based checks. If a request is blocked by any of these, further rule evaluations are skipped.

- **Rule Priority:**  
  Within each phase, rules are evaluated in the order they appear in the configuration file, with higher priority rules evaluated first.

- **Anomaly Scoring:**  
  The `anomaly_threshold` blocks requests that trigger multiple lower-severity rules by accumulating their scores.

- **Rule Action `block`:**  
  If a rule has the `block` action, the request is immediately blocked, regardless of the `anomaly_threshold` or other rules.

- **First Match Blocks (with Exception):**  
  If a rule matches and the request is blocked, processing stops immediately, except for rules with the `log` action, which only log the match and continue processing.

- **Custom Responses:**  
  Custom responses for blocked requests take precedence over the default blocking message.

- **Short Circuiting:**  
  If a request is blocked, processing stops immediately, saving resources and ensuring a fast response.

- **Response Processing:**  
  In Phases 3 and 4, the WAF evaluates the response being sent to the client. If the response is blocked, the configured custom response is returned instead.

---

## **Key Takeaways**

- **Ordered Processing:**  
  The WAF processes requests in a specific order, ensuring higher-priority checks are performed first.

- **Flexible Blocking:**  
  Requests can be blocked based on explicit rules, anomaly scores, country restrictions, rate limits, blacklists, or a combination of factors.

- **Customizable Behavior:**  
  The WAF is highly customizable through configuration options, allowing adaptation to specific security needs.

- **Efficient Handling:**  
  Short-circuiting ensures that once a request is blocked, no further processing is performed, improving performance.

- **Response Evaluation:**  
  The WAF evaluates responses and blocks them if necessary, ensuring only safe content is sent to the client.

---

## **Configuration Options**

The WAF provides a variety of configuration options to control its behavior. These options are typically set in the `Caddyfile`. Below is a detailed table of each option:

| **Option**               | **Description**                                                                                                                                                                                                 | **Example**                                                                                                        |
|--------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------|
| **`anomaly_threshold`**  | Sets the threshold for the anomaly score. Requests exceeding this score are blocked.                                                                                                                           | `anomaly_threshold 20`                                                                                             |
| **`rule_file`**          | Path to the JSON file containing the WAF's ruleset.                                                                                                                                                           | `rule_file rules.json`                                                                                             |
| **`ip_blacklist_file`**  | Path to the file containing blacklisted IP addresses and CIDR ranges.                                                                                                                                         | `ip_blacklist_file blacklist.txt`                                                                                  |
| **`dns_blacklist_file`** | Path to the file containing blacklisted domain names.                                                                                                                                                         | `dns_blacklist_file domains.txt`                                                                                   |
| **`rate_limit`**         | Configures rate limiting for incoming requests. Requires parameters like `requests`, `window`, and `cleanup_interval`.                                                                                        | `rate_limit { requests 100 window 1m cleanup_interval 5m paths /api/v1/.* match_all_paths false }`                 |
| **`block_countries`**    | Blocks requests from specified countries using the MaxMind GeoIP2 database.                                                                                                                                   | `block_countries GeoLite2-Country.mmdb RU CN`                                                                      |
| **`whitelist_countries`**| Whitelists requests from specified countries. Requests from non-whitelisted countries are blocked.                                                                                                            | `whitelist_countries GeoLite2-Country.mmdb US CA`                                                                  |
| **`log_severity`**       | Sets the minimum logging level (`debug`, `info`, `warn`, `error`).                                                                                                                                            | `log_severity info`                                                                                                |
| **`log_json`**           | Enables JSON format for log messages.                                                                                                                                                                         | `log_json`                                                                                                         |
| **`log_path`**           | Specifies the path for the WAF log file.                                                                                                                                                                      | `log_path /var/log/waf/access.log`                                                                                 |
| **`redact_sensitive_data`** | Redacts sensitive data from the request query string in logs.                                                                                                                                              | `redact_sensitive_data`                                                                                            |
| **`custom_response`**    | Defines custom HTTP responses for blocked requests. Requires status code, content type, and response content or file path.                                                                                    | `custom_response 403 application/json error.json`                                                                  |
| **`max_request_body_size`**| Configures request body size limit (default 10MB). Uses `io.LimitReader` for protection.                                                                                                    | `max_request_body_size 20MB`                                                                                       |
| **`block_asns`**         | Blocks requests from specified Autonomous Systems (ASNs) using the MaxMind GeoIP2 ASN database.                                                                                               | `block_asns GeoLite2-ASN.mmdb 12345 67890`                                                                         |
| **`geoip_fail_open`**    | Configures the WAF to allow requests if GeoIP/ASN lookup fails (Circuit Breaker pattern). Default is false (Fail Closed).                                                                     | `geoip_fail_open`                                                                                                  |

---

- **GeoIP:**  
> [!NOTE]
> The request will be geo-whitelisted if both `block_countries` and `whitelist_countries` are used and the same country code is specified on both directives. 

By carefully configuring these options, you can tailor the WAF's behavior to meet your specific security requirements, balancing protection with performance. Thorough testing after making changes is essential to ensure the WAF operates as expected. 
