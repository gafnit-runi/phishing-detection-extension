import json
from typing import Dict, List, Union, Any

def count_nodes_and_leaves(tree: Dict[str, Any]) -> tuple[int, int]:
    """Count total nodes and leaf nodes in a tree."""
    if tree.get('leaf'):
        return 1, 1
    
    left_nodes, left_leaves = count_nodes_and_leaves(tree['left']) if tree.get('left') else (0, 0)
    right_nodes, right_leaves = count_nodes_and_leaves(tree['right']) if tree.get('right') else (0, 0)
    
    total_nodes = 1 + left_nodes + right_nodes  # 1 for current node
    total_leaves = left_leaves + right_leaves
    
    return total_nodes, total_leaves

def get_leaf_values(tree: Dict[str, Any]) -> set:
    """Get all leaf values from a tree."""
    leaf_values = set()
    
    def collect_leaf_values(t):
        if t.get('leaf'):
            leaf_values.add(tuple(t['value']))
        else:
            if t.get('left'):
                collect_leaf_values(t['left'])
            if t.get('right'):
                collect_leaf_values(t['right'])
    
    collect_leaf_values(tree)
    return leaf_values

def pretty_print_tree(tree: Dict[str, Any], indent: str = "", is_last: bool = True, is_left: bool = True) -> None:
    """Pretty print a tree structure."""
    if tree.get('leaf'):
        print(f"{indent}└── {'L' if is_left else 'R'} Leaf: {tree['value']}")
        return

    print(f"{indent}└── {'L' if is_left else 'R'} Node: feature={tree.get('feature')}, threshold={tree.get('threshold')}")
    
    if tree.get('left'):
        pretty_print_tree(tree['left'], indent + "    ", False, True)
    if tree.get('right'):
        pretty_print_tree(tree['right'], indent + "    ", True, False)

def follow_path(tree: Dict[str, Any], path: str = "L→R→L→L→L→R→L→R") -> None:
    """Follow a specific path through the tree and print node values."""
    current = tree
    path_steps = path.split('→')[:-1]  # Remove last empty string
    
    print("\nFollowing path:", path)
    print("=" * 50)
    
    for i, step in enumerate(path_steps, 1):
        print(f"\nStep {i}: Going {step}")
        if current.get('leaf'):
            print("Reached leaf node!")
            print(f"Leaf value: {current['value']}")
            return
            
        print(f"Node value: {current.get('value', 'N/A')}")
        print(f"Feature: {current.get('feature', 'N/A')}")
        print(f"Threshold: {current.get('threshold', 'N/A')}")
        
        if step == 'L':
            current = current.get('left')
        else:
            current = current.get('right')
            
        if not current:
            print("Error: Path ended prematurely!")
            return
    
    if current.get('leaf'):
        print("\nFinal leaf node reached!")
        print(f"Leaf value: {current['value']}")
    else:
        print("\nPath completed. Subtree from this point:")
        print("=" * 50)
        pretty_print_tree(current, is_left=True)  # Root is considered left for consistency

def analyze_forest():
    """Load and analyze the random forest from the JSON file."""
    try:
        with open('phishing_detector.json', 'r') as f:
            forest_data = json.load(f)
        
        trees = forest_data.get('trees', [])
        print(f"\nAnalyzing Random Forest with {len(trees)} trees\n")
        print("=" * 80)

        # Print detailed analysis of first tree
        if trees:
            first_tree = trees[0]
            total_nodes, total_leaves = count_nodes_and_leaves(first_tree)
            
            print("\nDetailed analysis of first tree:")
            print(f"Total nodes: {total_nodes}")
            print(f"Total leaves: {total_leaves}")
            
            # Follow specific path through first tree
            follow_path(first_tree)
            print("\n" + "=" * 80)

    except FileNotFoundError:
        print("Error: phishing_detector.json not found")
    except json.JSONDecodeError:
        print("Error: Invalid JSON format in phishing_detector.json")
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    analyze_forest() 