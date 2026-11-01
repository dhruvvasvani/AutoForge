package com.autoforge.analyzer.graph;

import org.springframework.stereotype.Component;

import java.util.*;

@Component
public class CrossRepoGraphBuilder {
    private final Map<String, Map<String, Object>> serviceNodes = new HashMap<>();
    private final Map<String, List<Edge>> adjacencyList = new HashMap<>();

    public static class Edge {
        private final String targetService;
        private final String endpoint;

        public Edge(String targetService, String endpoint) {
            this.targetService = targetService;
            this.endpoint = endpoint;
        }

        public String getTargetService() {
            return targetService;
        }

        public String getEndpoint() {
            return endpoint;
        }
    }

    public void addServiceNode(String serviceName, Map<String, Object> metadata) {
        serviceNodes.put(serviceName, metadata != null ? metadata : new HashMap<>());
        adjacencyList.putIfAbsent(serviceName, new ArrayList<>());
    }

    public void addApiDependency(String sourceService, String targetService, String endpoint) {
        addServiceNode(sourceService, null);
        addServiceNode(targetService, null);
        adjacencyList.get(sourceService).add(new Edge(targetService, endpoint));
    }

    public List<String> findBlastRadius(String vulnerableService) {
        if (!adjacencyList.containsKey(vulnerableService)) {
            return Collections.emptyList();
        }

        Set<String> visited = new LinkedHashSet<>();
        Queue<String> queue = new LinkedList<>();
        queue.add(vulnerableService);

        while (!queue.isEmpty()) {
            String current = queue.poll();
            List<Edge> edges = adjacencyList.getOrDefault(current, Collections.emptyList());
            for (Edge edge : edges) {
                if (!visited.contains(edge.getTargetService()) && !edge.getTargetService().equals(vulnerableService)) {
                    visited.add(edge.getTargetService());
                    queue.add(edge.getTargetService());
                }
            }
        }

        return new ArrayList<>(visited);
    }

    public Map<String, Map<String, Object>> getServiceNodes() {
        return Collections.unmodifiableMap(serviceNodes);
    }
}
