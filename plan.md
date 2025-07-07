### **Implementation Plan: RapidAPI Feature Integration**

**Git Branching Strategy:**
*   [x] All new feature development will occur on dedicated feature branches, branched off `develop`.
*   [x] Each day's work will ideally correspond to a single feature branch or a logical part of one.
*   [x] Branches will be merged into `develop` and deleted upon completion and successful testing.

---

### **Phase 1: Core Feature Gating & Enhancements**

*   **Day 1: RapidAPI Plan Integration & Basic Feature Gating**
    *   [x] **Git Action:** Create branch `feature/rapidapi-gating` from `develop`.
    *   [x] **Objective:** Implement the logic to read the RapidAPI subscription header and gate existing features.
    *   **File Changes:**
        1.  [x] **Modify `api/app.py`**:
            *   [x] Import `request` from Flask (already there).
            *   [x] Inside the `check()` function, retrieve the `X-RapidAPI-Subscription` header:
                ```python
                user_plan = request.headers.get('X-RapidAPI-Subscription', 'BASIC').upper()
                ```
            *   [x] Implement conditional logic for `SOCKS Proxy Support` and `Proxy Authentication`:
                *   [x] If `user_plan` is `BASIC` and `proxy_type` is `socks4` or `socks5`, return a 403 Forbidden error with a message like "SOCKS proxy support requires a PRO plan or higher."
                *   [x] If `user_plan` is `BASIC` and `username` or `password` are provided in the request, return a 403 Forbidden error with a message like "Proxy authentication requires a PRO plan or higher."
            *   [x] Pass `user_plan` to the `check_proxy` function (you'll modify `check_proxy` later).
    *   [x] **Testing:** Manually test the `/check` endpoint with different `X-RapidAPI-Subscription` headers (simulated via `curl -H "X-RapidAPI-Subscription: BASIC"` etc.) and with SOCKS/auth parameters to ensure correct gating.
    *   [x] **Commit:** `feat: implement rapidapi plan gating for basic features` on `feature/rapidapi-gating`.

*   **Day 2: `check_proxy` Enhancements (SOCKS, Auth, ISP/ASN, Custom Target URL)**
    *   [x] **Git Action:** Continue on `feature/rapidapi-gating`.
    *   [x] **Objective:** Extend the `check_proxy` function to support new parameters and return new data points.
    *   **File Changes:**
        1.  [x] **Modify `proxy_checker/checker.py`**:
            *   [x] Update `check_proxy` function signature to accept `username`, `password`, `target_url` (all optional, with defaults).
            *   [x] Modify `requests.get` call to include `auth` parameter if `username` and `password` are provided.
            *   [x] Adjust proxy URL construction for SOCKS proxies (e.g., `socks5://`).
            *   [x] If `target_url` is provided, use it instead of `httpbin.org/ip`.
            *   [x] Add logic to fetch ISP/ASN data (e.g., from `ip-api.com` response) and include it in the returned dictionary.
        2.  [x] **Modify `api/app.py`**:
            *   [x] Pass `username`, `password`, `target_url` from the request body to the `check_proxy` function.
            *   [x] Implement conditional logic to filter `isp`, `asn` from the response if `user_plan` is `BASIC`.
    *   [x] **Testing:**
        *   [x] Update `tests/test_checker.py` to include unit tests for SOCKS, authentication, ISP/ASN data, and custom target URL.
        *   [x] Manually test `/check` with SOCKS proxies, authenticated proxies, and custom target URLs, verifying the output and gating.
    *   [x] **Commit:** `feat: enhance check_proxy for socks, auth, isp/asn, custom target` on `feature/rapidapi-gating`.

*   **Day 3: `check_proxy` Enhancements (DNS Leak, SSL Verification)**
    *   [x] **Git Action:** Continue on `feature/rapidapi-gating`.
    *   [x] **Objective:** Add more advanced checks to the `check_proxy` function.
    *   **File Changes:**
        1.  [x] **Modify `proxy_checker/checker.py`**:
            *   [x] Implement `dns_leak_test()` function: Make a request through the proxy to a DNS leak test service (e.g., `ipleak.net/json`), parse the response, and determine if a leak occurred.
            *   [x] Implement `ssl_verification()` function: For HTTPS proxies, perform a more thorough SSL certificate check (e.g., using `ssl` module or `requests` advanced features).
            *   [x] Integrate these functions into `check_proxy` and add `dns_leak_detected` and `ssl_verified` to the returned dictionary.
        2.  [x] **Modify `api/app.py`**:
            *   [x] Implement conditional logic to filter `dns_leak_detected` and `ssl_verified` from the response if `user_plan` is `BASIC` or `PRO`.
    *   [x] **Testing:**
        *   [x] Update `tests/test_checker.py` with unit tests for DNS leak and SSL verification.
        *   [x] Manually test `/check` with proxies that might exhibit these behaviors, verifying the output and gating.
    *   [x] **Commit:** `feat: add dns leak and ssl verification to proxy check` on `feature/rapidapi-gating`.

*   **Day 4: Reputation & Blacklist Check Integration**
    *   [x] **Git Action:** Continue on `feature/rapidapi-gating`.
    *   [x] **Objective:** Integrate an external service for proxy reputation and blacklist checking.
    *   **File Changes:**
        1.  [x] **Modify `proxy_checker/checker.py`**:
            *   [x] Add a new function `get_reputation_data(ip: str) -> dict`.
            *   [x] **Placeholder/Integration:** This function will call an external API (e.g., a paid service like IPQualityScore, or a free one if available and suitable) to get reputation/blacklist data. For initial implementation, it can return dummy data or a simple `True/False` for `blacklisted` and a fixed `reputation_score`.
            *   [x] Integrate this into `check_proxy` and add `reputation_score` and `blacklisted` to the returned dictionary.
        2.  [x] **Modify `api/app.py`**:
            *   [x] Implement conditional logic to filter `reputation_score` and `blacklisted` from the response if `user_plan` is `BASIC`, `PRO`, or `ULTRA`.
    *   [x] **Testing:**
        *   [x] Update `tests/test_checker.py` with unit tests for reputation/blacklist (mocking the external API call).
        *   [x] Manually test `/check` to verify the output and gating.
    *   [x] **Commit:** `feat: integrate proxy reputation and blacklist check` on `feature/rapidapi-gating`.

*   **Day 5: Phase 1 Testing & Refinement**
    *   [ ] **Git Action:** Merge `feature/rapidapi-gating` into `develop`. Delete `feature/rapidapi-gating`.
    *   [x] **Objective:** Ensure all feature gating and enhancements for the `/check` endpoint are stable.
    *   **Tasks:**
        1.  [x] Run all existing unit and integration tests (`pytest`). Fix any regressions.
        2.  [x] Perform comprehensive manual testing of the `/check` endpoint with various `X-RapidAPI-Subscription` headers and input parameters (SOCKS, auth, custom URL, etc.).
        3.  [x] Refine error messages and responses for clarity.
        4.  [x] Update `README.md` with details on new parameters and response fields for the `/check` endpoint.
    *   [x] **Commit:** `merge: complete phase 1 feature gating and check endpoint enhancements` on `develop`.

---

### **Phase 2: New Endpoints & Advanced Features**

*   **Day 6: Bulk Checking Endpoint (`/check/bulk`)**
    *   [x] **Git Action:** Create branch `feature/bulk-check` from `develop`.
    *   [x] **Objective:** Implement an endpoint for checking multiple proxies in a single request.
    *   **File Changes:**
        1.  [x] **Modify `api/app.py`**:
            *   [x] Add a new route `@app.route('/check/bulk', methods=['POST'])`.
            *   [x] Implement logic to read the `X-RapidAPI-Subscription` header. If `user_plan` is `BASIC` or `PRO`, return a 403 Forbidden error.
            *   [x] Parse the incoming JSON request, expecting a list of proxy objects.
            *   [x] Iterate through the list, calling `check_proxy` for each.
            *   [x] Return a JSON array of results.
            *   [x] Implement input validation for the bulk request (e.g., limit the number of proxies in a single batch to 100).
    *   [x] **Testing:**
        *   [x] Add new integration tests in `tests/test_api.py` for `/check/bulk` (valid requests, invalid requests, plan gating).
        *   [x] Manually test the endpoint with various batch sizes.
    *   [x] **Commit:** `feat: implement /check/bulk endpoint` on `feature/bulk-check`.

*   **Day 7: Asynchronous Processing (`/check/async` - Job Submission)**
    *   [x] **Git Action:** Continue on `feature/bulk-check` (or create `feature/async-check` if preferred to separate concerns).
    *   [x] **Objective:** Implement the endpoint for submitting asynchronous proxy checking jobs. This will require a background task queue (e.g., Celery with Redis/RabbitMQ) and a simple database (e.g., SQLite for job status).
    *   **File Changes:**
        1.  [x] **Add new dependencies:** Update `requirements.txt` for Celery, Redis/RabbitMQ client, etc.
        2.  [x] **Setup Celery:** Create `celery_worker.py` and configure Celery.
        3.  [x] **Modify `api/app.py`**:
            *   [x] Add a new route `@app.route('/check/async', methods=['POST'])`.
            *   [x] Implement logic to read the `X-RapidAPI-Subscription` header. If `user_plan` is `BASIC`, `PRO`, or `ULTRA`, return a 403 Forbidden error.
            *   [x] Parse the incoming JSON request (list of proxies, optional `callback_url`).
            *   [x] Generate a unique `job_id`.
            *   [x] Store job status (e.g., `submitted`) and proxy list in a simple database (e.g., SQLite file).
            *   [x] Dispatch a Celery task to process the proxies in the background.
            *   [x] Return `job_id` and `status: submitted`.
        4.  [x] **Modify `proxy_checker/checker.py`**:
            *   [x] Create a Celery task function that takes a list of proxies, processes them using `check_proxy`, updates job status in the database, and sends a webhook if `callback_url` is provided.
    *   [x] **Testing:**
        *   [x] Add integration tests for `/check/async` (job submission, plan gating).
        *   [x] Manually test job submission and verify job status in the database.
    *   [x] **Commit:** `feat: implement /check/async job submission` on `feature/bulk-check`.

*   **Day 8: Asynchronous Processing (`/check/async/{job_id}` & CSV Export)**
    *   [x] **Git Action:** Continue on `feature/bulk-check`.
    *   [x] **Objective:** Implement endpoints for retrieving asynchronous job results and CSV export.
    *   **File Changes:**
        1.  [x] **Modify `api/app.py`**:
            *   [x] Add a new route `@app.route('/check/async/<job_id>', methods=['GET'])`.
            *   [x] Retrieve job status and results from the database based on `job_id`.
            *   [x] Return job status and results (if completed).
            *   [x] Add a new route `@app.route('/check/async/<job_id>/csv', methods=['GET'])`.
            *   [x] Retrieve results for the `job_id`.
            *   [x] Convert results to CSV format and return as a file download.
        2.  [x] **Modify `proxy_checker/checker.py`**:
            *   [x] Add helper functions for CSV conversion.
    *   [x] **Testing:**
        *   [x] Add integration tests for `/check/async/{job_id}` (status, results) and `/check/async/{job_id}/csv`.
        *   [x] Manually test job retrieval and CSV download.
    *   [x] **Commit:** `feat: implement async job retrieval and csv export` on `feature/bulk-check`.

*   **Day 9: Alerts & Notifications (Placeholder/Integration)**
    *   [x] **Git Action:** Continue on `feature/bulk-check`.
    *   [x] **Objective:** Outline the implementation for alerts. This is likely a separate service or integration.
    *   **File Changes:**
        1.  [x] **Conceptual/Design:**
            *   [x] This feature would likely involve a user interface (dashboard) where users configure alert rules (e.g., "notify me if a proxy goes dead").
            *   [x] Your background worker (Celery task) would need to check these rules after each proxy check.
            *   [x] Integration with an external notification service (e.g., SendGrid for email, Twilio for SMS, or a webhook service).
        2.  [x] **Minimal API Changes (if any):**
            *   [x] Perhaps a new endpoint `/alerts/configure` to set up rules, but this might be better handled via a separate dashboard.
            *   [x] For now, focus on the conceptual integration.
    *   [x] **Testing:** N/A for direct API testing, but conceptual testing of the alert flow.
    *   [x] **Commit:** `docs: outline alerts and notifications feature` on `feature/bulk-check`.

*   **Day 10: Final Testing, Documentation Updates, and Release Preparation**
    *   [x] **Git Action:** Merge `feature/bulk-check` into `develop`. Delete `feature/bulk-check`.
    *   [x] **Objective:** Ensure all new features are stable, documented, and ready for deployment.
    *   **Tasks:**
        1.  [x] Run all unit and integration tests (`pytest`). Fix any regressions.
        2.  [x] Perform comprehensive manual testing of all new endpoints (`/check/bulk`, `/check/async`, `/check/async/{job_id}`, `/check/async/{job_id}/csv`) with various inputs and RapidAPI plan headers.
        3.  [x] Update `README.md` with documentation for all new endpoints, their parameters, and response formats.
        4.  [x] Update `proxy-checker-plan.md` to mark all steps as complete.
        5.  [x] **Release Preparation:**
            *   [x] Create `release/v2.0` branch from `develop`.
            *   [x] Perform final checks on the release branch.
            *   [x] Merge `release/v2.0` into `main` with a tag: `git tag -a v2.0 -m "Version 2.0 - Feature Expansion"`.
            *   [x] Merge `release/v2.0` back into `develop`.
            *   [x] Delete `release/v2.0`.
    *   [x] **Commit:** `merge: complete phase 2 feature implementation and release preparation` on `develop`.