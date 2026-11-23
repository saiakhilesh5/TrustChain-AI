"""Dependency graph: networkx DiGraph, root-to-component path tracing, pyvis rendering."""

import itertools
from pathlib import Path

import networkx as nx

ROOT = "ROOT"


def build_graph(inventory: dict) -> nx.DiGraph:
    """Build a directed graph: ROOT -> direct components -> transitive components."""
    graph = nx.DiGraph()
    graph.add_node(ROOT, label="application", scope="root", ecosystem="app", name="ROOT", version="")

    for comp in inventory["components"]:
        graph.add_node(
            comp["key"],
            label=f"{comp['name']}@{comp['version']}",
            name=comp["name"],
            version=comp["version"],
            scope=comp["scope"],
            ecosystem=comp["ecosystem"],
        )
    for comp in inventory["components"]:
        if comp["scope"] == "direct":
            graph.add_edge(ROOT, comp["key"])
        for dep in comp["resolved_deps"]:
            if graph.has_node(dep):
                graph.add_edge(comp["key"], dep)
    return graph


def paths_to_component(graph: nx.DiGraph, component_key: str, limit: int = 5) -> list[list[str]]:
    """All simple paths from ROOT to a component (capped), shortest first."""
    paths = list(itertools.islice(nx.all_simple_paths(graph, ROOT, component_key, cutoff=8), limit))
    return [list(path) for path in sorted(paths, key=len)]


def reachable_from_root(graph: nx.DiGraph) -> set[str]:
    return set(nx.descendants(graph, ROOT))


def trace_to_roots(graph: nx.DiGraph, component_key: str, limit: int = 5) -> list[list[str]]:
    """Shortest dependency chains from any direct dependency down to the component."""
    if component_key not in graph:
        return []
    direct = [n for n in graph.successors(ROOT) if n != component_key]
    paths = []
    for source in direct:
        try:
            path = nx.shortest_path(graph, source, component_key)
            paths.append(path)
        except nx.NetworkXNoPath:
            continue
    paths.sort(key=len)
    return paths[:limit]


def render_html(graph: nx.DiGraph, output: Path, max_nodes: int = 300, highlight: set[str] | None = None) -> Path:
    """Render an interactive dependency graph as HTML.

    Large graphs are reduced to ROOT, all direct components, and the most
    connected transitive components. Highlighted nodes (e.g. vulnerable) are
    always kept.
    """
    from pyvis.network import Network

    highlight = highlight or set()
    keep = {ROOT} | highlight
    if graph.number_of_nodes() > max_nodes:
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
    net = Network(
        height="900px", width="100%", directed=True, bgcolor="#111827",
        font_color="#e5e7eb", cdn_resources="remote",
    )
    for node, data in sub.nodes(data=True):
        if node == ROOT:
            net.add_node(node, label=data.get("label", node), color="#f59e0b", shape="diamond", size=25)
        elif node in highlight:
            net.add_node(node, label=data.get("label", node), color="#ef4444", size=18)
        elif data.get("scope") == "direct":
            net.add_node(node, label=data.get("label", node), color="#3b82f6", size=12)
        else:
            net.add_node(node, label=data.get("label", node), color="#6b7280", size=8)
    for source, target in sub.edges():
        color = "#ef4444" if target in highlight else "#374151"
        net.add_edge(source, target, color=color)
    net.force_atlas_2based(gravity=-50, spring_length=120)
    net.show(str(output), notebook=False)
    return output
