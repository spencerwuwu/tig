from collections import defaultdict
import json

def factor_sets(sets):
    tree = defaultdict(list)
    
    for s in sets:
        if not s:
            continue
        first, *rest = s
        #first, *rest = sorted(s)
        if rest:
            tree[first].append(set(rest))
        else:
            tree[first].append(set())
    
    result = {}
    for key, value in tree.items():
        factored = factor_sets(value)
        result[key] = factored if factored else value
    
    return [result] if result else []

if __name__ == "__main__":
    # Example usage
    sets = [{1,2,3}, {4,5,6}, {1, 9}, {1, 2, 6}, {4, 10}, {1, 11}]
    factored = factor_sets(sets)
    print(json.dumps(factored, indent=2))
