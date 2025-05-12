import joblib
import json

clf = joblib.load("random_forest_model_reduced.pkl")

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

#For debugging adding feature names
# forest_json["feature_names"] = clf.feature_names_in_.tolist()

# Save as JSON
with open("random_forest_model_reduced.json", "w") as f:
    json.dump(forest_json, f)

print("Model exported as random_forest_model_reduced.json")

scaler = joblib.load("scaler.pkl")

scaler_params = {
    "mean": scaler.mean_.tolist(),
    "scale": scaler.scale_.tolist()
}

with open("scaler_params.json", "w") as f:
    json.dump(scaler_params, f)

print("Scaler parameters exported to scaler_params.json")
