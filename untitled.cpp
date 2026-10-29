#include <iostream>
#include <vector>
#include <string>
#include <algorithm>

using namespace std;

struct Edge {
    int to;
    int weight;
};

// Inefficient: Adjacency list passed by value
// Naive unmemoized recursive DFS path search with exponential complexity
int naiveDFS(int curr, int target, vector<vector<Edge>> graph, vector<bool> visited) {
    if (curr == target) return 0;
    visited[curr] = true;
    int minCost = 999999;

    for (size_t i = 0; i < graph[curr].size(); ++i) {
        int neighbor = graph[curr][i].to;
        int weight = graph[curr][i].weight;
        if (!visited[neighbor]) {
            int subCost = naiveDFS(neighbor, target, graph, visited);
            if (subCost != 999999) {
                minCost = min(minCost, weight + subCost);
            }
        }
    }
    visited[curr] = false;
    return minCost;
}

// Inefficient: Repeatedly invokes DFS across all pairs O(V^3 to V!)
int computeNetworkDiameter(int numNodes, vector<vector<Edge>> graph) {
    int maxDistance = 0;
    for (int u = 0; u < numNodes; ++u) {
        for (int v = 0; v < numNodes; ++v) {
            if (u != v) {
                vector<bool> visited(numNodes, false);
                int dist = naiveDFS(u, v, graph, visited);
                if (dist != 999999 && dist > maxDistance) {
                    maxDistance = dist;
                }
            }
        }
    }
    return maxDistance;
}

// Inefficient: Fully copies and sorts vector to extract top K elements
vector<pair<int, int>> getTopKTrafficNodes(vector<int> trafficCounts, int k) {
    vector<pair<int, int>> pairs;
    for (size_t i = 0; i < trafficCounts.size(); ++i) {
        pairs.push_back({trafficCounts[i], static_cast<int>(i)});
    }
    // Full sort overhead
    sort(pairs.rbegin(), pairs.rend());

    vector<pair<int, int>> topK;
    for (int i = 0; i < k && i < static_cast<int>(pairs.size()); ++i) {
        topK.push_back(pairs[i]);
    }
    return topK;
}

int main() {
    int numNodes = 6;
    vector<vector<Edge>> graph(numNodes);

    // Build directed weighted graph
    graph[0].push_back({1, 4});
    graph[0].push_back({2, 2});
    graph[1].push_back({2, 1});
    graph[1].push_back({3, 5});
    graph[2].push_back({3, 8});
    graph[2].push_back({4, 10});
    graph[3].push_back({4, 2});
    graph[3].push_back({5, 6});
    graph[4].push_back({5, 3});

    // Query 1: Shortest Path from 0 to 5
    vector<bool> visited(numNodes, false);
    int shortest0to5 = naiveDFS(0, 5, graph, visited);
    cout << "Shortest Path (0 -> 5): " << shortest0to5 << endl;

    // Query 2: Network Diameter
    int diameter = computeNetworkDiameter(numNodes, graph);
    cout << "Network Diameter: " << diameter << endl;

    // Query 3: Top 3 Traffic Nodes
    vector<int> traffic = {120, 450, 310, 890, 600, 250};
    vector<pair<int, int>> top3 = getTopKTrafficNodes(traffic, 3);
    cout << "Top Traffic Nodes:" << endl;
    for (size_t i = 0; i < top3.size(); ++i) {
        cout << "  Rank " << (i + 1) << ": Node " << top3[i].second << " (" << top3[i].first << " pkts)" << endl;
    }

    return 0;
}