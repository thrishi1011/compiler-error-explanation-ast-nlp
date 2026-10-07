import os
import json
from typing import Dict, Any
from error_normalizer import normalize_error

DATA_DIR=os.path.join(os.path.dirname(os.path.dirname(__file__)),"data")
DATA_FILE=os.path.join(DATA_DIR,"training_data.json")

def log_example(error)->None:
    os.makedirs(DATA_DIR,exist_ok=True)
    
    # Normalize: use abstract semantic form for dataset storage
    dataset_message, _ = normalize_error(error.message)
    
    entry={
        "message": dataset_message,
        "raw_message": error.message,
        "category":error.category,
        "ast_node":getattr(error, "ast_node", ""),
        "explanation":error.explanation,
        "suggestion":error.suggestion,
        "confidence":error.confidence,
    }

    data=[]
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE,"r") as f:
                data=json.load(f)
        except Exception:
            data=[]

    for existing in data:
        if(
            existing.get("message")==entry["message"]
            and existing.get("category")==entry["category"]
        ):
            return

    data.append(entry)

    with open(DATA_FILE,"w") as f:
        json.dump(data,f,indent=2)