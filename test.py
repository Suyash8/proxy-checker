from proxy_checker.checker import check_proxy

# Test with a known proxy to see if it works
# Replace with a real proxy for testing
proxy = "123.45.67.89:8080"
proxy_type = "http"

result = check_proxy(proxy, proxy_type)
print(result)
