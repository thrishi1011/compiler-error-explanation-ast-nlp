#include <iostream>
#include <vector>
#include <string>
#include <queue>
#include <unordered_map>
#include <list>
#include <algorithm>
#include <climits>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <random>

using namespace std;

// ============================================================================
// MODULE 1: PREFIX TRIE FOR FAST STRING LOOKUPS
// ============================================================================
class TrieNode {
public:
    unordered_map<char, TrieNode*> children;
    bool isEndOfWord;

    TrieNode() {
        isEndOfWord = false;
    }
};

class Trie {
private:
    TrieNode* root;

    // Sub-optimal: passing string by value in recursive calls
    void collectWords(TrieNode* node, const string& prefix, vector<string>& results) {
        if (!node) return;
        if (node->isEndOfWord) {
            results.push_back(prefix);
        }
        for (auto& pair : node->children) {
            collectWords(pair.second, prefix + pair.first, results);
        }
    }

public:
    Trie() {
        root = new TrieNode();
    }

    void insert(string word) {
        TrieNode* current = root;
        for (char ch : word) {
            if (current->children.find(ch) == current->children.end()) {
                current->children[ch] = new TrieNode();
            }
            current = current->children[ch];
        }
        current->isEndOfWord = true;
    }

    bool search(string word) {
        TrieNode* current = root;
        for (char ch : word) {
            if (current->children.find(ch) == current->children.end()) {
                return false;
            }
            current = current->children[ch];
        }
        return current && current->isEndOfWord;
    }

    bool startsWith(string prefix) {
        TrieNode* current = root;
        for (char ch : prefix) {
            if (current->children.find(ch) == current->children.end()) {
                return false;
            }
            current = current->children[ch];
        }
        // ERROR 1: Missing semicolon
        return current != nullptr;
    }

    vector<string> autocomplete(string prefix) {
        vector<string> results;
        TrieNode* current = root;
        for (char ch : prefix) {
            if (current->children.find(ch) == current->children.end()) {
                return results;
            }
            current = current->children[ch];
        }
        collectWords(current, prefix, results);
        return results;
    }
};

// ============================================================================
// MODULE 2: LRU CACHE WITH DOUBLY LINKED LIST & HASH TABLE
// ============================================================================
class LRUCache {
private:
    int capacity;
    list<pair<int, int>> items; // key, value
    unordered_map<int, list<pair<int, int>>::iterator> cacheMap;

public:
    LRUCache(int cap) : capacity(cap) {}

    int get(int key) {
        if (cacheMap.find(key) == cacheMap.end()) {
            return -1;
        }
        // Move accessed item to front of list
        items.splice(items.begin(), items, cacheMap[key]);
        return cacheMap[key]->second;
    }

    void put(int key, int value) {
        if (cacheMap.find(key) != cacheMap.end()) {
            items.splice(items.begin(), items, cacheMap[key]);
            cacheMap[key]->second = value;
            return;
        }
        if ((int)items.size() >= capacity) {
            int oldKey = items.back().first;
            // ERROR 2: Missing semicolon
            items.pop_back();
            cacheMap.erase(oldKey);
        }
        items.push_front({key, value});
        cacheMap[key] = items.begin();
    }

    // ERROR 3: Missing return type (should be int)
    size() const {
        return items.size();
    }
};

// ============================================================================
// MODULE 3: DISJOINT SET UNION (UNION-FIND) WITH RANK & PATH COMPRESSION
// ============================================================================
class DisjointSet {
private:
    vector<int> parent;
    vector<int> rank;
    // ERROR 4: Missing type declaration (should be int)
    int components;


public:
    DisjointSet(int n) : components(n) {
        parent.resize(n);
        rank.resize(n, 0);
        for (int i = 0; i < n; i++) {
            parent[i] = i;
        }
    }

    int find(int i) {
        if (parent[i] == i)
            return i;
        return parent[i] = find(parent[i]); // Path compression
    }

    bool unite(int i, int j) {
        int rootI = find(i);
        int rootJ = find(j);
        if (rootI != rootJ) {
            if (rank[rootI] < rank[rootJ]) {
                parent[rootI] = rootJ;
            } else if (rank[rootI] > rank[rootJ]) {
                parent[rootJ] = rootI;
            } else {
                parent[rootJ] = rootI;
                rank[rootI]++;
            }
            components--;
            return true;
        }
        return false;
    }

    bool isConnected(int i, int j) {
        return find(i) == find(j);
    }

    int countComponents() const {
        return components;
    }
};

// ============================================================================
// MODULE 4: SEGMENT TREE FOR RANGE SUM AND RANGE MINIMUM QUERIES
// ============================================================================
class SegmentTree {
private:
    int n;
    vector<long long> tree;
    vector<long long> minTree;

    void build(const vector<int>& arr, int node, int start, int end) {
        if (start == end) {
            tree[node] = arr[start];
            minTree[node] = arr[start];
            return;
        }
        int mid = (start + end) / 2;
        build(arr, 2 * node, start, mid);
        build(arr, 2 * node + 1, mid + 1, end);
        tree[node] = tree[2 * node] + tree[2 * node + 1];
        minTree[node] = min(minTree[2 * node], minTree[2 * node + 1]);
    }

    void update(int node, int start, int end, int idx, int val) {
        if (start == end) {
            tree[node] = val;
            minTree[node] = val;
            return;
        }
        int mid = (start + end) / 2;
        if (start <= idx && idx <= mid)
            update(2 * node, start, mid, idx, val);
        else
            update(2 * node + 1, mid + 1, end, idx, val);
        tree[node] = tree[2 * node] + tree[2 * node + 1];
        minTree[node] = min(minTree[2 * node], minTree[2 * node + 1]);
    }

    long long querySum(int node, int start, int end, int l, int r) {
        if (r < start || end < l) return 0;
        if (l <= start && end <= r) return tree[node];
        int mid = (start + end) / 2;
        return querySum(2 * node, start, mid, l, r) +
               querySum(2 * node + 1, mid + 1, end, l, r);
    }

    long long queryMin(int node, int start, int end, int l, int r) {
        if (r < start || end < l) return LLONG_MAX;
        if (l <= start && end <= r) return minTree[node];
        int mid = (start + end) / 2;
        return min(queryMin(2 * node, start, mid, l, r),
                   queryMin(2 * node + 1, mid + 1, end, l, r));
    }

public:
    SegmentTree(const vector<int>& arr) {
        n = arr.size();
        tree.resize(4 * n, 0);
        minTree.resize(4 * n, LLONG_MAX);
        if (n > 0) build(arr, 1, 0, n - 1);
    }

    void update(int idx, int val) {
        update(1, 0, n - 1, idx, val);
    }

    long long querySum(int l, int r) {
        return querySum(1, 0, n - 1, l, r);
    }

    long long queryMin(int l, int r) {
        return queryMin(1, 0, n - 1, l, r);
    }
};

// ============================================================================
// MODULE 5: FENWICK TREE (BINARY INDEXED TREE)
// ============================================================================
class FenwickTree {
private:
    int n;
    vector<long long> bit;

public:
    FenwickTree(int size) : n(size), bit(size + 1, 0) {}

    void add(int idx, long long delta) {
        for (; idx <= n; idx += idx & -idx) {
            bit[idx] += delta;
        }
    }

    long long query(int idx) {
        long long sum = 0;
        for (; idx > 0; idx -= idx & -idx) {
            sum += bit[idx];
        }
        return sum;
    }

    long long queryRange(int l, int r) {
        return query(r) - query(l - 1);
    }
};

// ============================================================================
// MODULE 6: WEIGHTED GRAPH WITH DIJKSTRA'S SHORTEST PATH
// ============================================================================
struct Edge {
    int to;
    int weight;
};

class Graph {
private:
    int V;
    vector<vector<Edge>> adj;

public:
    Graph(int vertices) : V(vertices), adj(vertices) {}

    void addEdge(int u, int v, int w) {
        adj[u].push_back({v, w});
        adj[v].push_back({u, w}); // Undirected
    }

    vector<int> dijkstra(int src) {
        vector<int> dist(V, INT_MAX);
        priority_queue<pair<int, int>, vector<pair<int, int>>, greater<pair<int, int>>> pq;

        dist[src] = 0;
        pq.push({0, src});

        while (!pq.empty()) {
            int d = pq.top().first;
            int u = pq.top().second;
            pq.pop();

            if (d > dist[u]) continue;

            for (const auto& edge : adj[u]) {
                int v = edge.to;
                int weight = edge.weight;
                if (dist[u] + weight < dist[v]) {
                    dist[v] = dist[u] + weight;
                    pq.push({dist[v], v});
                }
            }
        }
        return dist;
    }
};

// ============================================================================
// MODULE 7: BINARY SEARCH TREE (BST)
// ============================================================================
struct BSTNode {
    int val;
    BSTNode* left;
    BSTNode* right;
    BSTNode(int v) : val(v), left(nullptr), right(nullptr) {}
};

class BinarySearchTree {
private:
    BSTNode* root;

    BSTNode* insert(BSTNode* node, int val) {
        if (!node) return new BSTNode(val);
        if (val < node->val)
            node->left = insert(node->left, val);
        else if (val > node->val)
            node->right = insert(node->right, val);
        return node;
    }

    bool search(BSTNode* node, int val) {
        if (!node) return false;
        if (node->val == val) return true;
        if (val < node->val) return search(node->left, val);
        return search(node->right, val);
    }

    void inorder(BSTNode* node, vector<int>& res) {
        if (!node) return;
        inorder(node->left, res);
        res.push_back(node->val);
        inorder(node->right, res);
    }

public:
    BinarySearchTree() : root(nullptr) {}

    void insert(int val) {
        root = insert(root, val);
    }

    bool search(int val) {
        return search(root, val);
    }

    vector<int> getInorder() {
        vector<int> res;
        inorder(root, res);
        return res;
    }
};

// ============================================================================
// MODULE 8: ALGORITHMIC BOTTLENECKS (O(N^2) SORTING & O(N^3) SEARCH)
// ============================================================================
class ComplexityLab {
public:
    // BOTTLENECK 1: O(N^2) Bubble Sort with pass-by-value overhead
    static vector<int> quadraticBubbleSort(vector<int> arr) {
        // [OPTIMIZED] Replaced O(N^2) bubble sort with O(N log N) std::sort
        sort(arr.begin(), arr.end());
        return arr;
    }

    // BOTTLENECK 2: O(N^3) Naive Subarray Sum Search
    static int naiveMaxSubarraySum(vector<int> arr) {
        // [OPTIMIZED] Replaced O(N^3) 3-nested loops with O(N) Kadane's algorithm
        int maxSum = INT_MIN, currentSum = 0;
        for (int x : arr) {
            currentSum = max(x, currentSum + x);
            maxSum = max(maxSum, currentSum);
        }
        return maxSum;
    }

    // BOTTLENECK 3: O(2^N) Naive Exponential Recursion
    static int naiveExponentialFib(int n) {
        // [OPTIMIZED] Replaced O(2^N) exponential recursion with O(N) iterative DP
        if (n <= 1) return n;
        int a = 0, b = 1;
        for (int i = 2; i <= n; i++) {
            int c = a + b;
            a = b;
            b = c;
        }
        return b;
    }

    // BOTTLENECK 4: O(N^2) Duplicate detection using nested linear scans
    static int countDuplicatesNaive(vector<int> arr) {
        // [OPTIMIZED] Replaced O(N^2) nested loop scan with O(N) hash-set lookup
        unordered_map<int, bool> seen;
        int duplicates = 0;
        for (int x : arr) {
            if (seen.find(x) != seen.end()) duplicates++;
            else seen[x] = true;
        }
        return duplicates;
    }
};

// ============================================================================
// MODULE 9: SYSTEM LOGGING & SECURITY LAB (5+ VULNERABILITIES FOR VULNGUARD)
// ============================================================================
class SecurityVulnerabilityLab {
public:
    // SECURITY 1: CWE-120 Buffer Copy without Checking Size (strcpy)
    static void exportUserSession(string username) {
        char buffer[32];
        snprintf(buffer, sizeof(buffer), "%s", username.c_str());
        cout << "[SecurityLab] Session exported for user: " << buffer << endl;
    }

    // SECURITY 2: CWE-676 Dangerous Function (sprintf) + CWE-338 Insecure PRNG (rand)
    static string generateWeakSessionId() {
        char token[64];
        int randomSalt = static_cast<int>(std::random_device{}() & 0x7fffffff) % 999999;
        snprintf(token, sizeof(token), "SESSION_AUTH_ID_%d", randomSalt);
        return string(token);
    }

    // SECURITY 3: CWE-78 OS Command Injection (system)
    static void runSystemDiagnostics(string inputPath) {
        string command = "echo Validating system path: " + inputPath;
    // [Unsafe system call neutralized for security]
    }

    // SECURITY 4: CWE-134 Format String Vulnerability (printf without specifier)
    static void logDiagnosticNotice(const char* noticeMessage) {
        printf("%s", noticeMessage);
        printf("\n");
    }

    // SECURITY 5: CWE-252 Unchecked Return Value on fopen
    static void writeLogMetric(const string& logData) {
        FILE* fp = fopen("benchmark_run.log", "w");
        fputs(logData.c_str(), fp);
        fclose(fp);
    }

    // SECURITY 6: CWE-457 Uninitialized Variable Used in Computation
    static int computeArrayChecksum(const vector<int>& nums) {
        int checksum = 0;
        for (int x : nums) {
            checksum += x;
        }
        return checksum;
    }
};

// ============================================================================
// MODULE 10: TEST HARNESS & BENCHMARK DRIVER
// ============================================================================
void testTrie() {
    cout << "\n[1/7] Testing Trie..." << endl;
    Trie trie;
    trie.insert("compiler");
    trie.insert("computation");
    trie.insert("complex");
    trie.insert("compile");

    cout << "Search 'compiler': " << (trie.search("compiler") ? "PASS" : "FAIL") << endl;
    cout << "Search 'unknown': " << (!trie.search("unknown") ? "PASS" : "FAIL") << endl;

    vector<string> matches = trie.autocomplete("comp");
    cout << "Autocomplete prefix 'comp': " << matches.size() << " results found." << endl;
}

void testLRU() {
    cout << "\n[2/7] Testing LRU Cache..." << endl;
    LRUCache lru(3);
    lru.put(1, 100);
    lru.put(2, 200);
    lru.put(3, 300);
    cout << "Get Key 1: " << lru.get(1) << " (expected 100)" << endl;
    lru.put(4, 400); // Evicts key 2
    cout << "Get Key 2 (evicted): " << lru.get(2) << " (expected -1)" << endl;
    cout << "Get Key 4: " << lru.get(4) << " (expected 400)" << endl;
}

void testDSU() {
    cout << "\n[3/7] Testing Disjoint Set Union..." << endl;
    DisjointSet dsu(7);
    dsu.unite(0, 1);
    dsu.unite(1, 2);
    dsu.unite(3, 4);
    cout << "0 connected to 2: " << (dsu.isConnected(0, 2) ? "YES" : "NO") << endl;
    cout << "0 connected to 3: " << (dsu.isConnected(0, 3) ? "YES" : "NO") << endl;
    cout << "Total disjoint components: " << dsu.countComponents() << endl;
}

void testSegmentTree() {
    cout << "\n[4/7] Testing Segment Tree..." << endl;
    vector<int> data = {1, 3, 5, 7, 9, 11};
    SegmentTree st(data);
    cout << "Range Sum [1, 3]: " << st.querySum(1, 3) << " (expected 15)" << endl;
    cout << "Range Min [2, 5]: " << st.queryMin(2, 5) << " (expected 5)" << endl;
    st.update(2, 2); // Change 5 to 2
    cout << "Updated Range Min [2, 5]: " << st.queryMin(2, 5) << " (expected 2)" << endl;
}

void testFenwickTree() {
    cout << "\n[5/7] Testing Fenwick Tree..." << endl;
    FenwickTree ft(10);
    ft.add(1, 5);
    ft.add(2, 3);
    ft.add(3, 7);
    ft.add(4, 2);
    cout << "Prefix sum to 3: " << ft.query(3) << " (expected 15)" << endl;
    cout << "Range sum [2, 4]: " << ft.queryRange(2, 4) << " (expected 12)" << endl;
}

void testGraphAndBST() {
    cout << "\n[6/7] Testing Dijkstra & BST..." << endl;
    Graph g(5);
    g.addEdge(0, 1, 4);
    g.addEdge(0, 2, 2);
    g.addEdge(1, 2, 1);
    g.addEdge(1, 3, 5);
    g.addEdge(2, 3, 8);
    g.addEdge(3, 4, 3);

    vector<int> distances = g.dijkstra(0);
    for (int i = 0; i < (int)distances.size(); i++) {
        cout << "Distance to node " << i << ": " << distances[i] << endl;
    }

    BinarySearchTree bst;
    bst.insert(50);
    bst.insert(30);
    bst.insert(70);
    bst.insert(20);
    bst.insert(40);
    cout << "BST In-order Traversal: ";
    for (int v : bst.getInorder()) cout << v << " ";
    cout << endl;
}

void testBottlenecksAndSecurity() {
    cout << "\n[7/7] Testing Complexity Lab & Security..." << endl;
    vector<int> testList = {45, 12, 85, 32, 89, 39, 69, 44, 42, 1, 45, 89};
    
    vector<int> sorted = ComplexityLab::quadraticBubbleSort(testList);
    cout << "Bubble Sorted Size: " << sorted.size() << " | First: " << sorted[0] << endl;
    
    int maxSub = ComplexityLab::naiveMaxSubarraySum(testList);
    cout << "Max Subarray Sum: " << maxSub << endl;
    
    int fib = ComplexityLab::naiveExponentialFib(8);
    cout << "Naive Fibonacci(8): " << fib << endl;
    
    int dupes = ComplexityLab::countDuplicatesNaive(testList);
    cout << "Duplicates Found: " << dupes << endl;

    // Triggering diagnostic methods for security analysis demonstration
    SecurityVulnerabilityLab::exportUserSession("AdminUser");
    string token = SecurityVulnerabilityLab::generateWeakSessionId();
    cout << "Weak Token Generated: " << token << endl;
    SecurityVulnerabilityLab::runSystemDiagnostics("usr/local/bin");
    SecurityVulnerabilityLab::logDiagnosticNotice("Audit log ready.");
    SecurityVulnerabilityLab::writeLogMetric("Run Completed");
    int chk = SecurityVulnerabilityLab::computeArrayChecksum(testList);
    cout << "Checksum computed: " << chk << endl;
}

int main() {
    cout << "============================================================" << endl;
    cout << "   COMPREHENSIVE DATA STRUCTURES & SECURITY AUDIT SUITE     " << endl;
    cout << "============================================================" << endl;

    testTrie();
    testLRU();
    testDSU();
    testSegmentTree();
    testFenwickTree();
    testGraphAndBST();
    testBottlenecksAndSecurity();

    cout << "\nAll test suites completed successfully!" << endl;
    return 0;
}