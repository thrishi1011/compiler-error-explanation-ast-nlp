/**
 * ==============================================================================
 * Test Case 11: Clean, Modern C++ Baseline (Zero False-Positive Verification)
 * ==============================================================================
 * Category: False Positive Resistance & Clean AST Extraction
 * Focus: Demonstrates compliant, secure, idiomatic modern C++ patterns.
 *
 * Verification Objectives:
 *   1. Compiles with 0 errors and 0 warnings (under -Wall -Wextra -std=c++14/c++17)
 *   2. Yields 0 Security Findings (0 CWEs, 0 CERT violations)
 *   3. Tests AST Extractor fidelity on modern C++ constructs:
 *      - Template classes and generic algorithms
 *      - Lambda expressions with capture lists
 *      - Smart pointers (std::unique_ptr)
 *      - std::vector, std::string, std::pair
 *      - Const-correct member functions and RAII resource handles
 * ==============================================================================
 */

#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <utility>
#include <algorithm>
#include <numeric>

// Clean RAII Resource Management Class
class SecureSessionManager {
public:
    explicit SecureSessionManager(std::string service_name)
        : m_service_name(std::move(service_name)), m_is_active(true) {}

    ~SecureSessionManager() {
        m_is_active = false;
    }

    // Const-correct inspector
    const std::string& get_service_name() const {
        return m_service_name;
    }

    bool is_active() const {
        return m_is_active;
    }

    void add_audit_entry(int event_id, std::string details) {
        m_audit_log.emplace_back(event_id, std::move(details));
    }

    bool find_event(int event_id, std::string& out_desc) const {
        for (const auto& entry : m_audit_log) {
            if (entry.first == event_id) {
                out_desc = entry.second;
                return true;
            }
        }
        return false;
    }

    size_t log_count() const {
        return m_audit_log.size();
    }

private:
    std::string m_service_name;
    bool m_is_active;
    std::vector<std::pair<int, std::string> > m_audit_log;
};

// Generic algorithm using templates and lambdas
template <typename T>
T calculate_filtered_average(const std::vector<T>& data, T threshold) {
    if (data.empty()) {
        return T(0);
    }

    std::vector<T> filtered;
    std::copy_if(data.begin(), data.end(), std::back_inserter(filtered),
                 [threshold](const T& val) { return val >= threshold; });

    if (filtered.empty()) {
        return T(0);
    }

    T sum = std::accumulate(filtered.begin(), filtered.end(), T(0));
    return sum / static_cast<T>(filtered.size());
}

// Bounded string inspection with bounds-safe access
void inspect_message(const std::string& message) {
    std::cout << "[INFO] Message length: " << message.length() << "\n";
    if (!message.empty()) {
        std::cout << "[INFO] First character: " << message.front() << "\n";
        std::cout << "[INFO] Last character:  " << message.back() << "\n";
    }
}

int main() {
    std::cout << "=== Running Clean C++ Benchmark (Baseline) ===\n";

    // 1. Smart pointer with RAII
    std::unique_ptr<SecureSessionManager> session(new SecureSessionManager("AuthenticationService"));
    session->add_audit_entry(1001, "User login succeeded");
    session->add_audit_entry(1002, "Certificate refreshed");

    std::cout << "Active Service: " << session->get_service_name() << "\n";
    std::cout << "Total logs: " << session->log_count() << "\n";

    std::string event_desc;
    if (session->find_event(1001, event_desc)) {
        std::cout << "Event 1001 Found: " << event_desc << "\n";
    }

    // 2. Vector with lambda processing
    std::vector<double> latency_metrics;
    latency_metrics.push_back(12.4);
    latency_metrics.push_back(18.2);
    latency_metrics.push_back(9.5);
    latency_metrics.push_back(45.1);
    latency_metrics.push_back(14.8);
    latency_metrics.push_back(16.0);

    double avg_high_latency = calculate_filtered_average(latency_metrics, 15.0);
    std::cout << "Average High Latency: " << avg_high_latency << " ms\n";

    // 3. String formatting
    std::string test_str = "Clean, Secure C++ Baseline Executed Successfully.";
    inspect_message(test_str);

    return 0;
}
