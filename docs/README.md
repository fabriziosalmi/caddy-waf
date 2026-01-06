# 🛡️ Caddy WAF Middleware Documentation

A robust, highly customizable, and feature-rich **Web Application Firewall (WAF)** middleware for the Caddy web server. This middleware provides **advanced protection** against a comprehensive range of web-based threats, seamlessly integrating with Caddy and offering flexible configuration options to secure your applications effectively.

This documentation provides everything you need to deploy and manage the Caddy WAF middleware effectively.

## 📑 Table of Contents

### 🚀 Getting Started

1.  **[Introduction](introduction.md)** - *Overview of the Caddy WAF, its purpose, and key benefits.*
2.  **[Installation](installation.md)** - *Instructions for installing the Caddy WAF middleware.* 
3.  **[Using caddy add-package](add-package-guide.md)** - *Quick guide for installing with the `caddy add-package` command.* 

### ⚙️ Core Configuration

3.  **[Configuration Options](configuration.md)** - *Detailed explanation of all available configuration settings, including how to set up the different options and settings of the WAF.*
4.  **[Rules Format (`rules.json`)](rules.md)** - *A comprehensive guide to defining custom rules using the JSON format, with details about all the fields available and examples on how to use them.*
5.   **[Blacklist Formats](blacklists.md)** - *Documentation of the formats used for defining IP and DNS blacklists, providing examples and guidelines for managing these files.*
6.   **[Rate Limiting](ratelimit.md)** - *How to configure rate limiting, including parameters, usage and caveats.*
7.  **[Country Blocking and Whitelisting](geoblocking.md)** - *Details on how to configure country-based blocking and whitelisting using the MaxMind GeoIP2 database, including how to obtain the necessary files.*

### 🛡️ Security Features

8.  **[Protected Attack Types](attacks.md)** - *An overview of the wide range of web-based threats that the Caddy WAF is designed to protect against.*
9. **[Dynamic Updates](dynamicupdates.md)** - *How to dynamically update the WAF rules and other settings without downtime or restarting the Caddy server.*

### 📊 Monitoring and Management

10. **[Metrics](metrics.md)** - *Details about the WAF's metrics endpoint and the different metrics collected, which provide insights into traffic patterns and WAF behavior, to help fine-tune the rules.*
11. **[Prometheus Metrics](prometheus.md)** - *Instructions on how to expose WAF metrics using the Prometheus format, for integration with your monitoring system.*
12. **[Rule/Blacklist Population Scripts](scripts.md)** - *Documentation on the provided scripts to automatically fetch, update and generate rules and blacklists from external resources.*

### 🧪 Testing and Deployment

13.  **[Testing](testing.md)** - *Guidance on how to test the WAF's effectiveness using the provided testing tools, with different ways of testing the WAF functionality.*
14.  **[Docker Support](docker.md)** - *Instructions on how to build and run the WAF using Docker, including best practices for containerized deployments.*

### 🖥️ Extending caddy-waf

15. **[ELK](https://github.com/fabriziosalmi/caddy-waf/blob/main/docs/caddy-waf-elk.md)** - *Observability of caddy-waf with ELK stack.*
16. **[Prometheus](https://github.com/fabriziosalmi/caddy-waf/blob/main/docs/prometheus.md)** - *Observability of caddy-waf with Prometheus.*
