from fastapi import HTTPException, status
from maquina_turing.turing_machine import SQLInjectionTuringMachine

turing_machine = SQLInjectionTuringMachine()

def check_query(query: str):
    is_malicious = turing_machine.is_malicious(query)
    
    if is_malicious:
        raise HTTPException(
            status_code=400,
            detail="Inyeccion SQL maliciosa detectada en la query."
        )
    
    response = {
        "message": "La query es segura",
        "query": query,
        "length": len(query),  
        "status": "Query valida",
        "http_status": 200 
    }

    if "SELECT" in query.upper():
        response["type"] = "Select query"
    elif "INSERT" in query.upper():
        response["type"] = "Insert query"
    elif "UPDATE" in query.upper():
        response["type"] = "Update query"
    elif "DELETE" in query.upper():
        response["type"] = "Delete query"
    else:
        response["type"] = "Other query"

    return response
