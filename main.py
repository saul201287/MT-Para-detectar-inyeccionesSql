import logging
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from maquina_turing import SQLInjectionTuringMachine

turing_machine = SQLInjectionTuringMachine()

app = FastAPI()

logger = logging.getLogger(__name__)
class QueryRequest(BaseModel):
    query: str

@app.middleware("http")
async def sql_injection_middleware(request: Request, call_next):
    try:
        body = await request.json()
        query = body.get("query", "")
        
        is_malicious = turing_machine.is_malicious(query)
        print(is_malicious)

        if is_malicious.get('message') != "La consulta es segura.":
            raise HTTPException(status_code=400, detail=is_malicious)
        else:
            return JSONResponse(content={"message": "Query segura"}, status_code=200)
        
        

    except HTTPException as e:
        if e.status_code == 400:
            return JSONResponse(content={"detail": e.detail}, status_code=400)
        return JSONResponse(content={"detail": "Internal server error"}, status_code=500)

@app.post("/check_query")
async def check_query(query: QueryRequest):
    return {"message": "Query processed successfully", "query": query.query}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
