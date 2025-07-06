### **Implementation Plan: RapidAPI Feature Integration**

**Git Branching Strategy:**
*   [ ] All new feature development will occur on dedicated feature branches, branched off `develop`.
*   [ ] Each day's work will ideally correspond to a single feature branch or a logical part of one.
*   [ ] Branches will be merged into `develop` and deleted upon completion and successful testing.

---

### **Phase 1: Core Feature Gating & Enhancements**

*   **Day 1: RapidAPI Plan Integration & Basic Feature Gating**
    *   [ ] **Git Action:** Create branch `feature/rapidapi-gating` from `develop`.
    *   [ ] **Objective:** Implement the logic to read the RapidAPI subscription header and gate existing features.
    *   **File Changes:**
        1.  [ ] **Modify `api/app.py`**:
            *   [ ] Import `request` from Flask (already there).
            *   [ ] Inside the `check()` function, retrieve the `X-RapidAPI-Subscription` header:
                ```python
                user_plan = request.headers.get('X-RapidAPI-Subscription', 'BASIC').upper()
                ```
            *   [ ] Implement conditional logic for `SOCKS Proxy Support` and `Proxy Authentication`:
                *   [ ] If `user_plan` is `BASIC` and `proxy_type` is `socks4` or `socks5`, return a 403 Forbidden error with a message like "SOCKS proxy support requires a PRO plan or higher."
                *   [ ] If `user_plan` is `BASIC` and `username` or `password` are provided in the request, return a 403 Forbidden error with a message like "Proxy authentication requires a PRO plan or higher."
            *   [ ] Pass `user_plan` to the `check_proxy` function (you'll modify `check_proxy` later).
    *   [ ] **Testing:** Manually test the `/check` endpoint with different `X-RapidAPI-Subscription` headers (simulated via `curl -H "X-RapidAPI-Subscription: BASIC"` etc.) and with SOCKS/auth parameters to ensure correct gating.
    *   [ ] **Commit:** `feat: implement rapidapi plan gating for basic features` on `feature/rapidapi-gating`.

*   **Day 2: `check_proxy` Enhancements (SOCKS, Auth, ISP/ASN, Custom Target URL)**
    *   [ ] **Git Action:** Continue on `feature/rapidapi-gating`.
    *   [ ] **Objective:** Extend the `check_proxy` function to support new parameters and return new data points.
    *   **File Changes:**
        1.  [ ] **Modify `proxy_checker/checker.py`**:
            *   [ ] Update `check_proxy` function signature to accept `username`, `password`, `target_url` (all optional, with defaults).
            *   [ ] Modify `requests.get` call to include `auth` parameter if `username` and `password` are provided.
            *   [ ] Adjust proxy URL construction for SOCKS proxies (e.g., `socks5://`).
            *   [ ] If `target_url` is provided, use it instead of `httpbin.org/ip`.
            *   [ ] Add logic to fetch ISP/ASN data (e.g., from `ip-api.com` response) and include it in the returned dictionary.
        2.  [ ] **Modify `api/app.py`**:
            *   [ ] Pass `username`, `password`, `target_url` from the request body to the `check_proxy` function.
            *   [ ] Implement conditional logic to filter `isp`, `asn` from the response if `user_plan` is `BASIC`.
    *   [ ] **Testing:**
        *   [ ] Update `tests/test_checker.py` to include unit tests for SOCKS, authentication, ISP/ASN data, and custom target URL.
        *   [ ] Manually test `/check` with SOCKS proxies, authenticated proxies, and custom target URLs, verifying the output and gating.
    *   [ ] **Commit:** `feat: enhance check_proxy for socks, auth, isp/asn, custom target` on `feature/rapidapi-gating`.

*   **Day 3: `check_proxy` Enhancements (DNS Leak, SSL Verification)**
    *   [ ] **Git Action:** Continue on `feature/rapidapi-gating`.
    *   [ ] **Objective:** Add more advanced checks to the `check_proxy` function.
    *   **File Changes:**
        1.  [ ] **Modify `proxy_checker/checker.py`**:
            *   [ ] Implement `dns_leak_test()` function: Make a request through the proxy to a DNS leak test service (e.g., `ipleak.net/json`), parse the response, and determine if a leak occurred.
            *   [ ] Implement `ssl_verification()` function: For HTTPS proxies, perform a more thorough SSL certificate check (e.g., using `ssl` module or `requests` advanced features).
            *   [ ] Integrate these functions into `check_proxy` and add `dns_leak_detected` and `ssl_verified` to the returned dictionary.
        2.  [ ] **Modify `api/app.py`**:
            *   [ ] Implement conditional logic to filter `dns_leak_detected` and `ssl_verified` from the response if `user_plan` is `BASIC` or `PRO`.
    *   [ ] **Testing:**
        *   [ ] Update `tests/test_checker.py` with unit tests for DNS leak and SSL verification.
        *   [ ] Manually test `/check` with proxies that might exhibit these behaviors, verifying the output and gating.
    *   [ ] **Commit:** `feat: add dns leak and ssl verification to proxy check` on `feature/rapidapi-gating`.

*   **Day 4: Reputation & Blacklist Check Integration**
    *   [ ] **Git Action:** Continue on `feature/rapidapi-gating`.
    *   [ ] **Objective:** Integrate an external service for proxy reputation and blacklist checking.
    *   **File Changes:**
        1.  [ ] **Modify `proxy_checker/checker.py`**:
            *   [ ] Add a new function `get_reputation_data(ip: str) -> dict`.
            *   [ ] **Placeholder/Integration:** This function will call an external API (e.g., a paid service like IPQualityScore, or a free one if available and suitable) to get reputation/blacklist data. For initial implementation, it can return dummy data or a simple `True/False` for `blacklisted` and a fixed `reputation_score`.
            *   [ ] Integrate this into `check_proxy` and add `reputation_score` and `blacklisted` to the returned dictionary.
        2.  [ ] **Modify `api/app.py`**:
            *   [ ] Implement conditional logic to filter `reputation_score` and `blacklisted` from the response if `user_plan` is `BASIC`, `PRO`, or `ULTRA`.
    *   [ ] **Testing:**
        *   [ ] Update `tests/test_checker.py` with unit tests for reputation/blacklist (mocking the external API call).
        *   [ ] Manually test `/check` to verify the output and gating.
    *   [ ] **Commit:** `feat: integrate proxy reputation and blacklist check` on `feature/rapidapi-gating`.

*   **Day 5: Phase 1 Testing & Refinement**
    *   [ ] **Git Action:** Merge `feature/rapidapi-gating` into `develop`. Delete `feature/rapidapi-gating`.
    *   [ ] **Objective:** Ensure all feature gating and enhancements for the `/check` endpoint are stable.
    *   **Tasks:**
        1.  [ ] Run all existing unit and integration tests (`pytest`). Fix any regressions.
        2.  [ ] Perform comprehensive manual testing of the `/check` endpoint with various `X-RapidAPI-Subscription` headers and input parameters (SOCKS, auth, custom URL, etc.).
        3.  [ ] Refine error messages and responses for clarity.
        4.  [ ] Update `README.md` with details on new parameters and response fields for the `/check` endpoint.
    *   [ ] **Commit:** `merge: complete phase 1 feature gating and check endpoint enhancements` on `develop`.

---

### **Phase 2: New Endpoints & Advanced Features**

*   **Day 6: Bulk Checking Endpoint (`/check/bulk`)**
    *   [ ] **Git Action:** Create branch `feature/bulk-check` from `develop`.
    *   [ ] **Objective:** Implement an endpoint for checking multiple proxies in a single request.
    *   **File Changes:**
        1.  [ ] **Modify `api/app.py`**:
            *   [ ] Add a new route `@app.route('/check/bulk', methods=['POST'])`.
            *   [ ] Implement logic to read the `X-RapidAPI-Subscription` header. If `user_plan` is `BASIC` or `PRO`, return a 403 Forbidden error.
            *   [ ] Parse the incoming JSON request, expecting a list of proxy objects.
            *   [ ] Iterate through the list, calling `check_proxy` for each.
            *   [ ] Return a JSON array of results.
            *   [ ] Implement input validation for the bulk request (e.g., limit the number of proxies in a single batch to 100).
    *   [ ] **Testing:**
        *   [ ] Add new integration tests in `tests/test_api.py` for `/check/bulk` (valid requests, invalid requests, plan gating).
        *   [ ] Manually test the endpoint with various batch sizes.
    *   [ ] **Commit:** `feat: implement /check/bulk endpoint` on `feature/bulk-check`.

*   **Day 7: Asynchronous Processing (`/check/async` - Job Submission)**
    *   [ ] **Git Action:** Continue on `feature/bulk-check` (or create `feature/async-check` if preferred to separate concerns).
    *   [ ] **Objective:** Implement the endpoint for submitting asynchronous proxy checking jobs. This will require a background task queue (e.g., Celery with Redis/RabbitMQ) and a simple database (e.g., SQLite for job status).
    *   **File Changes:**
        1.  [ ] **Add new dependencies:** Update `requirements.txt` for Celery, Redis/RabbitMQ client, etc.
        2.  [ ] **Setup Celery:** Create `celery_worker.py` and configure Celery.
        3.  [ ] **Modify `api/app.py`**:
            *   [ ] Add a new route `@app.route('/check/async', methods=['POST'])`.
            *   [ ] Implement logic to read the `X-RapidAPI-Subscription` header. If `user_plan` is `BASIC`, `PRO`, or `ULTRA`, return a 403 Forbidden error.
            *   [ ] Parse the incoming JSON request (list of proxies, optional `callback_url`).
            *   [ ] Generate a unique `job_id`.
            *   [ ] Store job status (e.g., `submitted`) and proxy list in a simple database (e.g., SQLite file).
            *   [ ] Dispatch a Celery task to process the proxies in the background.
            *   [ ] Return `job_id` and `status: submitted`.
        4.  [ ] **Modify `proxy_checker/checker.py`**:
            *   [ ] Create a Celery task function that takes a list of proxies, processes them using `check_proxy`, updates job status in the database, and sends a webhook if `callback_url` is provided.
    *   [ ] **Testing:**
        *   [ ] Add integration tests for `/check/async` (job submission, plan gating).
        *   [ ] Manually test job submission and verify job status in the database.
    *   [ ] **Commit:** `feat: implement /check/async job submission` on `feature/bulk-check`.

*   **Day 8: Asynchronous Processing (`/check/async/{job_id}` & CSV Export)**
    *   [ ] **Git Action:** Continue on `feature/bulk-check`.
    *   [ ] **Objective:** Implement endpoints for retrieving asynchronous job results and CSV export.
    *   **File Changes:**
        1.  [ ] **Modify `api/app.py`**:
            *   [ ] Add a new route `@app.route('/check/async/<job_id>', methods=['GET'])`.
            *   [ ] Retrieve job status and results from the database based on `job_id`.
            *   [ ] Return job status and results (if completed).
            *   [ ] Add a new route `@app.route('/check/async/<job_id>/csv', methods=['GET'])`.
            *   [ ] Retrieve results for the `job_id`.
            *   [ ] Convert results to CSV format and return as a file download.
        2.  [ ] **Modify `proxy_checker/checker.py`**:
            *   [ ] Add helper functions for CSV conversion.
    *   [ ] **Testing:**
        *   [ ] Add integration tests for `/check/async/{job_id}` (status, results) and `/check/async/{job_id}/csv`.
        *   [ ] Manually test job retrieval and CSV download.
    *   [ ] **Commit:** `feat: implement async job retrieval and csv export` on `feature/bulk-check`.

*   **Day 9: Alerts & Notifications (Placeholder/Integration)**
    *   [ ] **Git Action:** Continue on `feature/bulk-check`.
    *   [ ] **Objective:** Outline the implementation for alerts. This is likely a separate service or integration.
    *   **File Changes:**
        1.  [ ] **Conceptual/Design:**
            *   [ ] This feature would likely involve a user interface (dashboard) where users configure alert rules (e.g., "notify me if a proxy goes dead").
            *   [ ] Your background worker (Celery task) would need to check these rules after each proxy check.
            *   [ ] Integration with an external notification service (e.g., SendGrid for email, Twilio for SMS, or a webhook service).
        2.  [ ] **Minimal API Changes (if any):**
            *   [ ] Perhaps a new endpoint `/alerts/configure` to set up rules, but this might be better handled via a separate dashboard.
            *   [ ] For now, focus on the conceptual integration.
    *   [ ] **Testing:** N/A for direct API testing, but conceptual testing of the alert flow.
    *   [ ] **Commit:** `docs: outline alerts and notifications feature` on `feature/bulk-check`.

*   **Day 10: Final Testing, Documentation Updates, and Release Preparation**
    *   [ ] **Git Action:** Merge `feature/bulk-check` into `develop`. Delete `feature/bulk-check`.
    *   [ ] **Objective:** Ensure all new features are stable, documented, and ready for deployment.
    *   **Tasks:**
        1.  [ ] Run all unit and integration tests (`pytest`). Fix any regressions.
        2.  [ ] Perform comprehensive manual testing of all new endpoints (`/check/bulk`, `/check/async`, `/check/async/{job_id}`, `/check/async/{job_id}/csv`) with various inputs and RapidAPI plan headers.
        3.  [ ] Update `README.md` with documentation for all new endpoints, their parameters, and response formats.
        4.  [ ] Update `proxy-checker-plan.md` to mark all steps as complete.
        5.  [ ] **Release Preparation:**
            *   [ ] Create `release/v2.0` branch from `develop`.
            *   [ ] Perform final checks on the release branch.
            *   [ ] Merge `release/v2.0` into `main` with a tag: `git tag -a v2.0 -m "Version 2.0 - Feature Expansion"`.
            *   [ ] Merge `release/v2.0` back into `develop`.
            *   [ ] Delete `release/v2.0`.
    *   [ ] **Commit:** `merge: complete phase 2 feature implementation and release preparation` on `develop`.