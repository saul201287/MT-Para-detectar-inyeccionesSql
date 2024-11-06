from fastapi import APIRouter
from pydantic import BaseModel
from controller.query_controller import check_query

router = APIRouter()

class QueryRequest(BaseModel):
    query: str

@router.post("/check_query/")
async def check_query_endpoint(request: QueryRequest):
    print("22")
    return check_query(request.query)
