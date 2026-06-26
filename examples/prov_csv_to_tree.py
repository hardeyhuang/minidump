#!/usr/bin/env python3
"""Convert an indirect-memory provenance CSV (produced by
SetMiniDumpInprocIndirectProvenanceReportW) into an indented tree view.

Each captured 4KB page is a node. Layer-1 nodes (parent_index == -1) are the
roots and carry their origin (a CPU register or a stack slot). Deeper nodes are
linked to their parent page via parent_index, and the edge is annotated with the
exact slot inside the parent page (source_addr) and the raw pointer value found
there (pointer_value).

Usage:
    python prov_csv_to_tree.py <report.prov.csv> [-o <out.tree.txt>]
                               [--drop-sentinels]

--drop-sentinels  hides pages whose pointer_value is 0xFFFFFFFFFFFFFFFF
                  (sentinel / invalid slots), along with their subtrees.
"""
import argparse
import csv
import sys


def load_rows(path):
    rows = []
    with open(path, "r", encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            r["index"] = int(r["index"])
            r["layer"] = int(r["layer"])
            r["parent_index"] = int(r["parent_index"])
            rows.append(r)
    return rows


def node_label(r, is_root):
    page = r["page"]
    if is_root:
        if r["source"] == "register":
            origin = "REG %s" % r["register"]
        elif r["source"] == "stack":
            origin = "STACK[%s]" % r["source_addr"]
        else:
            origin = r["source"]
        return "%s  <- %s @T%s" % (page, origin, r["thread_id"])
    # transitive page: show where in the parent the pointer was found
    return "%s  <- [%s] = %s" % (page, r["source_addr"], r["pointer_value"])


def build_tree(rows, drop_sentinels):
    by_index = {r["index"]: r for r in rows}
    children = {}
    roots = []
    for r in rows:
        if drop_sentinels and r["pointer_value"].lower() == "0x" + "f" * 16:
            continue
        p = r["parent_index"]
        if p == -1:
            roots.append(r)
        else:
            children.setdefault(p, []).append(r)
    for lst in children.values():
        lst.sort(key=lambda x: x["index"])
    roots.sort(key=lambda x: x["index"])
    return by_index, children, roots


def render(rows, drop_sentinels):
    _, children, roots = build_tree(rows, drop_sentinels)
    out = []
    shown = [0]

    def walk(node, prefix, is_last, is_root):
        shown[0] += 1
        if is_root:
            branch = ""
        else:
            branch = ("└─ " if is_last else "├─ ")
        out.append("%s%s%s" % (prefix, branch, node_label(node, is_root)))
        kids = children.get(node["index"], [])
        if is_root:
            child_prefix = prefix
        else:
            child_prefix = prefix + ("   " if is_last else "│  ")
        for i, kid in enumerate(kids):
            walk(kid, child_prefix, i == len(kids) - 1, False)

    for ri, root in enumerate(roots):
        walk(root, "", True, True)
        if ri != len(roots) - 1:
            out.append("")
    header = "%d root(s), %d page(s) shown%s" % (
        len(roots), shown[0],
        " (sentinels dropped)" if drop_sentinels else "")
    return header + "\n" + ("=" * len(header)) + "\n\n" + "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("-o", "--out")
    ap.add_argument("--drop-sentinels", action="store_true")
    args = ap.parse_args()

    rows = load_rows(args.csv)
    text = render(rows, args.drop_sentinels)
    out_path = args.out or (args.csv.rsplit(".csv", 1)[0] + ".tree.txt")
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    sys.stdout.write("wrote %s\n" % out_path)


if __name__ == "__main__":
    main()
