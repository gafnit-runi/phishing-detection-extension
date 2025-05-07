import joblib
import json

clf = joblib.load("phishing_detector.pkl")

def tree_to_dict(tree):
    tree_ = tree.tree_

    def recurse(node):
        if tree_.feature[node] != -2:  # Not a leaf node
            return {
                "feature": int(tree_.feature[node]),
                "threshold": float(tree_.threshold[node]),
                "left": recurse(tree_.children_left[node]),
                "right": recurse(tree_.children_right[node])
            }
        else:  # Leaf node
            value = tree_.value[node][0].tolist()
            return {
                "leaf": True,
                "value": value
            }

    return recurse(0)

forest_json = {
    "n_classes": clf.n_classes_,
    "n_features": clf.n_features_in_,
    "trees": [tree_to_dict(tree) for tree in clf.estimators_]
}

# Save as JSON
with open("phishing_detector.json", "w") as f:
    json.dump(forest_json, f)

print("✅ Model exported as phishing_detector.json")
