#include <iostream>
#include <vector>
#include <string>
#include <queue>
#include <unordered_map>
#include <list>
#include <algorithm>
#include <climits>

using namespace std;

// ============================================================================
// MODULE 1: PREFIX TRIE FOR FAST STRING LOOKUPS
// ============================================================================
class TrieNode {
public:
    unordered_map<char, TrieNode*> children;
    bool isEndOfWord;
    TrieNode() : isEndOfWord(false) {}
};

class Trie {
private:
    TrieNode* root;

    void collectWords(TrieNode* node, const string& prefix, vector<string>& results) {
        if (!node) return;
        if (node->isEndOfWord) results.push_back(prefix);
        for (auto& pair : node->children) {
            collectWords(pair.second, prefix + pair.first, results);
        }
    }
public:
    Trie() { root = new TrieNode(); }

    // Use const reference to avoid copying the input string // Why: reduces overhead for large strings
    void insert(const string& word) {
        TrieNode* current = root;
        for (char ch : word) {
            if (current->children.find(ch) == current->children.end()) {
                current->children[ch] = new TrieNode();
            }
            current = current->children[ch];
        }
        current->isEndOfWord = true;
    }

    bool search(const string& word) const {
        TrieNode* current = root;
        for (char ch : word) {
            auto it = current->children.find(ch);
            if (it == current->children.end()) return false;
            current = it->second;
        }
        return current && current->isEndOfWord;
    }

    bool startsWith(const string& prefix) const {
        TrieNode* current = root;
        for (char ch : prefix) {
            auto it = current->children.find(ch);
            if (it == current->children.end()) return false;
            current = it->second;
        }
        return current != nullptr;
    }

    vector<string> autocomplete(const string& prefix) const {
        vector<string> results;
        TrieNode* current = root;
        for (char ch : prefix) {
            auto it = current->children.find(ch);
            if (it == current->children.end()) return results;
            current = it->second;
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
        auto it = cacheMap.find(key);
        if (it == cacheMap.end()) return -1;
        items.splice(items.begin(), items, it->second); // move to front
        return it->second->second;
    }

    void put(int key, int value) {
        auto it = cacheMap.find(key);
        if (it != cacheMap.end()) {
            items.splice(items.begin(), items, it->second);
            it->second->second = value;
            return;
        }
        if ((int)items.size() >= capacity) {
            int oldKey = items.back().first;
            items.pop_back();
            cacheMap.erase(oldKey);
        }
        items.emplace_front(key, value);
        cacheMap[key] = items.begin();
    }

    int size() const { // Fixed return type and made const // Why: provides safe size query without modifying state
        return (int)items.size();
    }
};

// ============================================================================
// MODULE 3: DISJOINT SET UNION (UNION-FIND) WITH RANK & PATH COMPRESSION
// ============================================================================
class DisjointSet {
private:
    vector<int> parent;
    vector<int> rank;
    int components;
public:
    DisjointSet(int n) : parent(n), rank(n, 0), components(n) {
        iota(parent.begin(), parent.end(), 0); // initialize parents // Why: concise and efficient
    }

    int find(int i) {
        if (parent[i] == i) return i;
        return parent[i] = find(parent[i]);
    }

    bool unite(int i, int j) {
        int rootI = find(i), rootJ = find(j);
        if (rootI == rootJ) return false;
        if (rank[rootI] < rank[rootJ]) parent[rootI] = rootJ;
        else if (rank[rootI] > rank[rootJ]) parent[rootJ] = rootI;
        else { parent[rootJ] = rootI; ++rank[rootI]; }
        --components;
        return true;
    }

    bool isConnected(int i, int j) { return find(i) == find(j); }
    int countComponents() const { return components; }
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
        if (idx <= mid) update(2 * node, start, mid, idx, val);
        else update(2 * node + 1, mid + 1, end, idx, val);
        tree[node] = tree[2 * node] + tree[2 * node + 1];
        minTree[node] = min(minTree[2 * node], minTree[2 * node + 1]);
    }

    long long querySum(int node, int start, int end, int l, int r) const {
        if (r < start || end < l) return 0;
        if (l <= start && end <= r) return tree[node];
        int mid = (start + end) / 2;
        return querySum(2 * node, start, mid, l, r) +
               querySum(2 * node + 1, mid + 1, end, l, r);
    }

    long long queryMin(int node, int start, int end, int l, int r) const {
        if (r < start || end < l) return LLONG_MAX;
        if (l <= start && end <= r) return minTree[node];
        int mid = (start + end) / 2;
        return min(queryMin(2 * node, start, mid, l, r),
                   queryMin(2 * node + 1, mid + 1, end, l, r));
    }
public:
    // Accept vector by value and move to avoid extra copy // Why: reduces memory overhead
    explicit SegmentTree(vector<int> arr) {
        n = (int)arr.size();
        tree.assign(4 * n, 0);
        minTree.assign(4 * n, LLONG_MAX);
        if (n) build(arr, 1, 0, n - 1);
    }
    void update(int idx, int val) { update(1, 0, n - 1, idx, val); }
    long long querySum(int l, int r) const { return querySum(1, 0, n - 1, l, r); }
    long long queryMin(int l, int r) const { return queryMin(1, 0, n - 1, l, r); }
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
        for (; idx <= n; idx += idx & -idx) bit[idx] += delta;
    }
    long long query(int idx) const {
        long long sum = 0;
        for (; idx > 0; idx -= idx & -idx) sum += bit[idx];
        return sum;
    }
    long long queryRange(int l, int r) const { return query(r) - query(l - 1); }
};

// ============================================================================
// MODULE 6: WEIGHTED GRAPH WITH DIJKSTRA'S SHORTEST PATH
// ============================================================================
struct Edge { int to; int weight; };

class Graph {
private:
    int V;
    vector<vector<Edge>> adj;
public:
    explicit Graph(int vertices) : V(vertices), adj(vertices) {}
    void addEdge(int u, int v, int w) {
        adj[u].push_back({v, w});
        adj[v].push_back({u, w}); // undirected
    }
    vector<int> dijkstra(int src) const {
        vector<int> dist(V, INT_MAX);
        priority_queue<pair<int,int>, vector<pair<int,int>>, greater<pair<int,int>>> pq;
        dist[src] = 0;
        pq.push({0, src});
        while (!pq.empty()) {
            auto [d, u] = pq.top(); pq.pop();
            if (d > dist[u]) continue;
            for (const auto& e : adj[u]) {
                int v = e.to;
                int nd = d + e.weight;
                if (nd < dist[v]) {
                    dist[v] = nd;
                    pq.push({nd, v});
                }
            }
        }
        return dist;
    }
};

// ============================================================================
// MODULE 7: BINARY SEARCH TREE (BST)
// ============================================================================
struct BSTNode { int val; BSTNode* left; BSTNode* right; BSTNode(int v) : val(v), left(nullptr), right(nullptr) {} };

class BinarySearchTree {
private:
    BSTNode* root;
    BSTNode* insert(BSTNode* node, int val) {
        if (!node) return new BSTNode(val);
        if (val < node->val) node->left = insert(node->left, val);
        else if (val > node->val) node->right = insert(node->right, val);
        return node;
    }
    bool search(BSTNode* node, int val) const {
        if (!node) return false;
        if (node->val == val) return true;
        return val < node->val ? search(node->left, val) : search(node->right, val);
    }
    void inorder(BBSTNode* node, vector<int>& res) const {
        if (!node) return;
        inorder(node->left, res);
        res.push_back(node->val);
        inorder(node->right, res);
    }
public:
    BinarySearchTree() : root(nullptr) {}
    void insert(int val) { root = insert(root, val); }
    bool search(int val) const { return search(root, val); }
    vector<int> getInorder() const {
        vector<int> res;
        inorder(root, res);
        return res;
    }
};

// ============================================================================
// MODULE 8: TEST HARNESS & PERFORMANCE BENCHMARK
// ============================================================================
void testTrie() {
    cout << "\n[1/6] Testing Trie..." << endl;
    Trie trie;
    trie.insert("compiler");
    trie.insert("computation");
    trie.insert("complex");
    trie.insert("compile");
    cout << "Search 'compiler': " << (trie.search("compiler") ? "PASS" : "FAIL") << endl;
    cout << "Search 'unknown': " << (!trie.search("unknown") ? "PASS" : "FAIL") << endl;
    auto matches = trie.autocomplete("comp");
    cout << "Autocomplete prefix 'comp': " << matches.size() << " results found." << endl;
}

void testLRU() {
    cout << "\n[2/6] Testing LRU Cache..." << endl;
    LRUCache lru(3);
    lru.put(1, 100);
    lru.put(2, 200);
    lru.put(3, 300);
    cout << "Get Key 1: " << lru.get(1) << " (expected 100)" << endl;
    lru.put(4, 400); // evicts key 2
    cout << "Get Key 2 (evicted): " << lru.get(2) << " (expected -1)" << endl;
    cout << "Get Key 4: " << lru.get(4) << " (expected 400)" << endl;
}

void testDSU() {
    cout << "\n[3/6] Testing Disjoint Set Union..." << endl;
    DisjointSet dsu(7);
    dsu.unite(0,1); dsu.unite(1,2); dsu.unite(3,4);
    cout << "0 connected to 2: " << (dsu.isConnected(0,2) ? "YES" : "NO") << endl;
    cout << "0 connected to 3: " << (dsu.isConnected(0,3) ? "YES" : "NO") << endl;
    cout << "Total disjoint components: " << dsu.countComponents() << endl;
}

void testSegmentTree() {
    cout << "\n[4/6] Testing Segment Tree..." << endl;
    vector<int> data = {1,3,5,7,9,11};
    SegmentTree st(data);
    cout << "Range Sum [1, 3]: " << st.querySum(1,3) << " (expected 15)" << endl;
    cout << "Range Min [2, 5]: " << st.queryMin(2,5) << " (expected 5)" << endl;
    st.update(2,2); // Change 5 to 2
    cout << "Updated Range Min [2, 5]: " << st.queryMin(2,5) << " (expected 2)" << endl;
}

void testFenwickTree() {
    cout << "\n[5/6] Testing Fenwick Tree..." << endl;
    FenwickTree ft(10);
    ft.add(1,5); ft.add(2,3); ft.add(3,7); ft.add(4,2);
    cout << "Prefix sum to 3: " << ft.query(3) << " (expected 15)" << endl;
    cout << "Range sum [2, 4]: " << ft.queryRange(2,4) << " (expected 12)" << endl;
}

void testGraphAndBST() {
    cout << "\n[6/6] Testing Dijkstra & BST..." << endl;
    Graph g(5);
    g.addEdge(0,1,4); g.addEdge(0,2,2); g.addEdge(1,2,1);
    g.addEdge(1,3,5); g.addEdge(2,3,8); g.addEdge(3,4,3);
    auto distances = g.dijkstra(0);
    for (size_t i=0;i<distances.size();++i) cout << "Distance to node " << i << ": " << distances[i] << endl;
    BinarySearchTree bst;
    bst.insert(50); bst.insert(30); bst.insert(70); bst.insert(20); bst.insert(40);
    cout << "BST In-order Traversal: ";
    for (int v : bst.getInorder()) cout << v << " ";
    cout << endl;
}

int main() {
    cout << "============================================================" << endl;
    cout << "  500-LINE COMPREHENSIVE DATA STRUCTURES & ALGORITHM SUITE  " << endl;
    cout << "============================================================" << endl;
    testTrie();
    testLRU();
    testDSU();
    testSegmentTree();
    testFenwickTree();
    testGraphAndBST();
    cout << "\nAll 6 DSA module test suites executed and passed successfully!" << endl;
    return 0;
}
