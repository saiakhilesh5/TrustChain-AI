"""Convert a networkx dependency graph into a vis.js-friendly JSON payload."""

from trustchain.graph.depgraph import ROOT


def build_graph_payload(graph, highlight: set[str], max_nodes: int = 400) -> dict:
    """Nodes + edges for the web UI, reduced like render_html for large graphs."""
    highlight = set(highlight or [])
    total_nodes = graph.number_of_nodes()
    keep = {ROOT} | highlight
    if total_nodes > max_nodes:
        for node, data in graph.nodes(data=True):
            if data.get("scope") == "direct" and len(keep) < max_nodes:
                keep.add(node)
        remaining = sorted(
            (n for n in graph if n not in keep),
            key=lambda n: graph.degree(n),
            reverse=True,
        )
        for node in remaining:
            if len(keep) >= max_nodes:
                break
            keep.add(node)
    else:
        keep.update(graph.nodes)

    sub = graph.subgraph(keep)
    nodes = []
    for node, data in sub.nodes(data=True):
        if node == ROOT:
            group, color, size = "root", "#f59e0b", 25
        elif node in highlight:
            group, color, size = "vulnerable", "#ef4444", 18
        elif data.get("scope") == "direct":
            group, color, size = "direct", "#3b82f6", 12
        else:
            group, color, size = "transitive", "#6b7280", 8
        nodes.append({
            "id": node,
            "label": data.get("label", node),
            "group": group,
            "color": color,
            "size": size,
            "title": f"{node} [{group}]",
        })
    edges = [
        {
            "from": source,
            "to": target,
            "color": "#ef4444" if target in highlight else "#374151",
            "arrows": "to",
        }
        for source, target in sub.edges()
    ]
    return {
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "total_nodes": total_nodes,
            "total_edges": graph.number_of_edges(),
            "shown_nodes": len(nodes),
            "shown_edges": len(edges),
            "vulnerable": len(highlight),
        },
    }
